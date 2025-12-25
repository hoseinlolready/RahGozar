package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	DBPath       = "./forwarder.db"
	PollInterval = 3 * time.Second
	SaveInterval = 5 * time.Second
	BufSize      = 512 * 1024
)

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, BufSize)
		return &b
	},
}

type Rule struct {
	ID         int
	ListenPort int
	TargetIP   string
	TargetPort int
	LimitBytes int64
	BytesUsed  int64
	ExpiryDate int64
	Active     int
}

type StatsTracker struct {
	mu     sync.RWMutex
	counts map[int]*uint64
}

func (st *StatsTracker) GetCounter(ruleID int) *uint64 {
	st.mu.RLock()
	c, ok := st.counts[ruleID]
	st.mu.RUnlock()
	if ok {
		return c
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if c, ok := st.counts[ruleID]; ok {
		return c
	}
	var newCounter uint64 = 0
	st.counts[ruleID] = &newCounter
	return &newCounter
}

func (st *StatsTracker) Reset(ruleID int) uint64 {
	counter := st.GetCounter(ruleID)
	return atomic.SwapUint64(counter, 0)
}

type ServerManager struct {
	listeners map[int]net.Listener
	configs   map[int]string 
	tracker   *StatsTracker
	db        *sql.DB
	mu        sync.Mutex
}

func main() {
	log.SetFlags(log.Ltime)
	log.SetPrefix("[RahGozar CORE] ")

	pubIP := getPublicIP()
	log.Printf("RahGozar Core Running. IP: %s", pubIP)

	db, err := sql.Open("sqlite3", DBPath)
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}
	defer db.Close()

	// 4. Initialize Manager
	tracker := &StatsTracker{counts: make(map[int]*uint64)}
	manager := &ServerManager{
		listeners: make(map[int]net.Listener),
		configs:   make(map[int]string),
		tracker:   tracker,
		db:        db,
	}

	go runStatsSaver(db, tracker)
	
	ticker := time.NewTicker(PollInterval)
	for range ticker.C {
		if err := manager.SyncRules(); err != nil {
			log.Printf("Error syncing rules: %v", err)
		}
	}
}


func (m *ServerManager) SyncRules() error {
	rows, err := m.db.Query("SELECT id, listen_port, target_ip, target_port, limit_bytes, bytes_used, expiry_date FROM rules WHERE active=1")
	if err != nil {
		return err
	}
	defer rows.Close()

	activeRules := make(map[int]bool)
	now := time.Now().Unix()

	for rows.Next() {
		var r Rule
		err := rows.Scan(&r.ID, &r.ListenPort, &r.TargetIP, &r.TargetPort, &r.LimitBytes, &r.BytesUsed, &r.ExpiryDate)
		if err != nil {
			log.Printf("Row scan error: %v", err)
			continue
		}

		if r.LimitBytes > 0 && r.BytesUsed >= r.LimitBytes {
			continue
		}
		if r.ExpiryDate > 0 && now > r.ExpiryDate {
			continue
		}

		activeRules[r.ID] = true
		configHash := fmt.Sprintf("%d:%s:%d", r.ListenPort, r.TargetIP, r.TargetPort)

		m.mu.Lock()
		currentHash, exists := m.configs[r.ID]
		m.mu.Unlock()

		if !exists || currentHash != configHash {
			if exists {
				m.StopServer(r.ID)
			}
			go m.StartServer(r, configHash)
		}
	}

	m.mu.Lock()
	for id := range m.listeners {
		if !activeRules[id] {
			m.StopServerLocked(id)
		}
	}
	m.mu.Unlock()

	return nil
}

func (m *ServerManager) StartServer(r Rule, hash string) {
	addr := fmt.Sprintf(":%d", r.ListenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Failed to listen on port %d: %v", r.ListenPort, err)
		return
	}

	m.mu.Lock()
	m.listeners[r.ID] = ln
	m.configs[r.ID] = hash
	m.mu.Unlock()

	log.Printf("Started Rule %d: %d -> %s:%d", r.ID, r.ListenPort, r.TargetIP, r.TargetPort)

	counter := m.tracker.GetCounter(r.ID)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		
		go handleConnection(conn, r.TargetIP, r.TargetPort, counter)
	}
}

func (m *ServerManager) StopServer(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.StopServerLocked(id)
}

func (m *ServerManager) StopServerLocked(id int) {
	if ln, ok := m.listeners[id]; ok {
		ln.Close()
		delete(m.listeners, id)
		delete(m.configs, id)
		log.Printf("Stopped Rule %d", id)
	}
}


func handleConnection(src net.Conn, targetIP string, targetPort int, counter *uint64) {
	defer src.Close()

	if tcpConn, ok := src.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
	}

	dest, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetIP, targetPort), 5*time.Second)
	if err != nil {
		return
	}
	defer dest.Close()

	if tcpConn, ok := dest.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	
	errChan := make(chan error, 2)

	go func() {
		errChan <- pipe(src, dest, counter)
	}()

	go func() {
		errChan <- pipe(dest, src, counter)
	}()

	<-errChan
}

func pipe(src, dst net.Conn, counter *uint64) error {
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			
			if nw > 0 {
				atomic.AddUint64(counter, uint64(nw))
			}
			
			if ew != nil {
				return ew
			}
			if nr != nw {
				return io.ErrShortWrite
			}
		}
		if er != nil {
			return er
		}
	}
}

func runStatsSaver(db *sql.DB, tracker *StatsTracker) {
	ticker := time.NewTicker(SaveInterval)
	for range ticker.C {
		tracker.mu.RLock()
		ids := make([]int, 0, len(tracker.counts))
		for id := range tracker.counts {
			ids = append(ids, id)
		}
		tracker.mu.RUnlock()

		if len(ids) == 0 {
			continue
		}

		tx, err := db.Begin()
		if err != nil {
			log.Printf("DB Tx Error: %v", err)
			continue
		}

		stmt, err := tx.Prepare("UPDATE rules SET bytes_used = bytes_used + ? WHERE id = ?")
		if err != nil {
			tx.Rollback()
			continue
		}

		updatesCount := 0
		for _, id := range ids {
			usage := tracker.Reset(id)
			if usage > 0 {
				_, err := stmt.Exec(usage, id)
				if err != nil {
					log.Printf("Update Stats Error Rule %d: %v", id, err)
				} else {
					updatesCount++
				}
			}
		}

		stmt.Close()
		if updatesCount > 0 {
			if err := tx.Commit(); err != nil {
				log.Printf("DB Commit Error: %v", err)
			}
		} else {
			tx.Rollback()
		}
	}
}


func getPublicIP() string {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "127.0.0.1"
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body)
}
