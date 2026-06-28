package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	pollInterval = 2 * time.Second
	saveInterval = 5 * time.Second
	bufSize      = 256 * 1024
)

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, bufSize)
		return &b
	},
}

type counter struct {
	up   uint64
	down uint64
}

type liveRate struct {
	upBps   float64
	downBps float64
}

type Manager struct {
	db *sql.DB

	mu        sync.Mutex
	listeners map[int64]net.Listener
	configs   map[int64]string // ruleID -> "port:ip:port" so we can detect edits
	counters  map[int64]*counter

	rateMu sync.RWMutex
	rates  map[int64]liveRate
}

func newManager(db *sql.DB) *Manager {
	return &Manager{
		db:        db,
		listeners: make(map[int64]net.Listener),
		configs:   make(map[int64]string),
		counters:  make(map[int64]*counter),
		rates:     make(map[int64]liveRate),
	}
}

func (m *Manager) getCounter(id int64) *counter {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.counters[id]
	if !ok {
		c = &counter{}
		m.counters[id] = c
	}
	return c
}

func (m *Manager) Run() {
	go m.statsLoop()
	go m.periodicResetLoop()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for range ticker.C {
		if err := m.sync(); err != nil {
			log.Printf("sync error: %v", err)
		}
	}
}

func (m *Manager) sync() error {
	nowTs := now()
	wantDebug := getSetting(m.db, "debug", "off") == "on"
	if wantDebug != debugFlag.Load() && !debugForced {
		if wantDebug {
			log.Printf("debug logging enabled")
		} else {
			log.Printf("debug logging disabled")
		}
	}
	setDebugFlag(wantDebug)
	ratio := getUsageRatio(m.db)
	suspended := suspendedOwners(m.db, ratio)

	rows, err := m.db.Query(`SELECT id, owner, name, role, mode, secret, host, listen_port, target_ip, target_port,
		limit_bytes, bytes_up, bytes_down, period, period_reset_at, expiry_date, note,
		icmp_src_ip, icmp_listen_ip, icmp_peer_ip, active, created_at
		FROM rules WHERE active = 1`)
	if err != nil {
		return err
	}
	defer rows.Close()

	wanted := make(map[int64]Rule)

	for rows.Next() {
		var r Rule
		var active int
		if err := rows.Scan(&r.ID, &r.Owner, &r.Name, &r.Role, &r.Mode, &r.Secret, &r.Host,
			&r.ListenPort, &r.TargetIP, &r.TargetPort,
			&r.LimitBytes, &r.BytesUp, &r.BytesDown, &r.Period, &r.PeriodResetAt, &r.ExpiryDate,
			&r.Note, &r.ICMPSrcIP, &r.ICMPListenIP, &r.ICMPPeerIP, &active, &r.CreatedAt); err != nil {
			log.Printf("row scan: %v", err)
			continue
		}

		if suspended[r.Owner] {
			continue // owner account is suspended (expired or over their quota)
		}
		if r.LimitBytes > 0 && int64(float64(r.BytesUp+r.BytesDown)*ratio) >= r.LimitBytes {
			continue // over quota, do not run
		}
		if r.ExpiryDate > 0 && nowTs > r.ExpiryDate {
			continue // expired, do not run
		}
		wanted[r.ID] = r
	}

	for id, r := range wanted {
		hash := fmt.Sprintf("%s|%s|%s|%s|%d:%s:%d|%s|%s|%s", r.Role, r.Mode, r.Secret, r.Host, r.ListenPort, r.TargetIP, r.TargetPort,
			r.ICMPSrcIP, r.ICMPListenIP, r.ICMPPeerIP)

		m.mu.Lock()
		cur, exists := m.configs[id]
		m.mu.Unlock()

		if !exists || cur != hash {
			if exists {
				m.stop(id)
			}
			go m.start(r, hash)
		}
	}

	m.mu.Lock()
	for id := range m.listeners {
		if _, ok := wanted[id]; !ok {
			m.stopLocked(id)
		}
	}
	m.mu.Unlock()

	return nil
}

func (m *Manager) start(r Rule, hash string) {
	opt := TransportOpt{Secret: r.Secret, Host: r.Host,
		ICMPSrcIP: r.ICMPSrcIP, ICMPListenIP: r.ICMPListenIP, ICMPPeerIP: r.ICMPPeerIP}
	listenAddr := fmt.Sprintf(":%d", r.ListenPort)
	targetAddr := fmt.Sprintf("%s:%d", r.TargetIP, r.TargetPort)

	isSIT := r.Mode == "sit" && (r.Role == "server" || r.Role == "client")
	if isSIT {
		if r.Role == "server" {
			if _, e := ensureSIT(r.ListenPort, r.TargetIP, true); e != nil {
				log.Printf("tunnel #%d sit setup failed: %v", r.ID, e)
				return
			}
			targetAddr = fmt.Sprintf("127.0.0.1:%d", r.TargetPort)
		} else {
			peerPriv, e := ensureSIT(r.TargetPort, r.TargetIP, false)
			if e != nil {
				log.Printf("tunnel #%d sit setup failed: %v", r.ID, e)
				return
			}
			targetAddr = fmt.Sprintf("%s:%d", peerPriv, r.TargetPort)
		}
	}

	var ln net.Listener
	var err error

	switch {
	case r.Role == "server" && !isSIT:
		t, terr := getTransport(r.Mode)
		if terr != nil {
			log.Printf("tunnel #%d: %v", r.ID, terr)
			return
		}
		ln, err = t.Listen(listenAddr, opt)

	default: // client, local, or any SIT role: plain TCP listener
		ln, err = net.Listen("tcp", listenAddr)
	}

	if err != nil {
		log.Printf("listen :%d failed (role=%s mode=%s): %v", r.ListenPort, r.Role, r.Mode, err)
		return
	}

	m.mu.Lock()
	m.listeners[r.ID] = ln
	m.configs[r.ID] = hash
	m.mu.Unlock()

	modeLabel := r.Mode
	if r.Role == "client" || r.Role == "server" {
		log.Printf("tunnel #%d up [%s/%s]: :%d <-> %s (owner=%s)", r.ID, r.Role, modeLabel, r.ListenPort, targetAddr, r.Owner)
	} else {
		log.Printf("tunnel #%d up [forward]: :%d -> %s (owner=%s)", r.ID, r.ListenPort, targetAddr, r.Owner)
	}

	c := m.getCounter(r.ID)

	dialOut := func() (net.Conn, error) { return dialTimeout(targetAddr) }
	if r.Role == "client" && !isSIT {
		t, terr := getTransport(r.Mode)
		if terr != nil {
			log.Printf("tunnel #%d: %v", r.ID, terr)
			ln.Close()
			return
		}
		dialOut = func() (net.Conn, error) { return t.Dial(targetAddr, opt) }
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		go handleConn(conn, dialOut, c)
	}
}

func (m *Manager) stop(id int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked(id)
}

func (m *Manager) stopLocked(id int64) {
	if ln, ok := m.listeners[id]; ok {
		ln.Close()
		delete(m.listeners, id)
		delete(m.configs, id)
		log.Printf("tunnel #%d down", id)
	}
}

func handleConn(src net.Conn, dialOut func() (net.Conn, error), c *counter) {
	defer src.Close()
	if t, ok := src.(*net.TCPConn); ok {
		t.SetNoDelay(true)
	}

	dst, err := dialOut()
	if err != nil {
		return
	}
	defer dst.Close()
	if t, ok := dst.(*net.TCPConn); ok {
		t.SetNoDelay(true)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pipe(src, dst, &c.up)
		halfCloseWrite(dst)
	}()
	go func() {
		defer wg.Done()
		pipe(dst, src, &c.down)
		halfCloseWrite(src)
	}()
	wg.Wait()
}

func halfCloseWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

func pipe(src, dst net.Conn, counted *uint64) {
	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				atomic.AddUint64(counted, uint64(nw))
			}
			if ew != nil || nw != nr {
				return
			}
		}
		if er != nil {
			return
		}
	}
}

func (m *Manager) statsLoop() {
	ticker := time.NewTicker(saveInterval)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		ids := make([]int64, 0, len(m.counters))
		for id := range m.counters {
			ids = append(ids, id)
		}
		m.mu.Unlock()
		if len(ids) == 0 {
			continue
		}

		tx, err := m.db.Begin()
		if err != nil {
			log.Printf("stats tx begin: %v", err)
			continue
		}
		stmt, err := tx.Prepare("UPDATE rules SET bytes_up = bytes_up + ?, bytes_down = bytes_down + ? WHERE id = ?")
		if err != nil {
			tx.Rollback()
			continue
		}

		newRates := make(map[int64]liveRate, len(ids))
		for _, id := range ids {
			c := m.getCounter(id)
			up := atomic.SwapUint64(&c.up, 0)
			down := atomic.SwapUint64(&c.down, 0)
			if up > 0 || down > 0 {
				if _, err := stmt.Exec(up, down, id); err != nil {
					log.Printf("stats update rule %d: %v", id, err)
				}
			}
			newRates[id] = liveRate{
				upBps:   float64(up) / saveInterval.Seconds(),
				downBps: float64(down) / saveInterval.Seconds(),
			}
		}
		stmt.Close()
		tx.Commit()

		m.rateMu.Lock()
		m.rates = newRates
		m.rateMu.Unlock()
	}
}

func (m *Manager) Rate(id int64) (float64, float64) {
	m.rateMu.RLock()
	defer m.rateMu.RUnlock()
	r := m.rates[id]
	return r.upBps, r.downBps
}

func (m *Manager) IsRunning(id int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.listeners[id]
	return ok
}

func (m *Manager) periodicResetLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	m.applyPeriodicResets()
	for range ticker.C {
		m.applyPeriodicResets()
	}
}

func (m *Manager) applyPeriodicResets() {
	rows, err := m.db.Query("SELECT id, period, period_reset_at FROM rules WHERE period != 'none'")
	if err != nil {
		return
	}
	type pending struct {
		id   int64
		next int64
	}
	var due []pending
	nowTs := now()
	for rows.Next() {
		var id, resetAt int64
		var period string
		if err := rows.Scan(&id, &period, &resetAt); err != nil {
			continue
		}
		if resetAt == 0 {
			due = append(due, pending{id, nextPeriodReset(period, time.Now()).Unix()})
			continue
		}
		if nowTs >= resetAt {
			due = append(due, pending{id, nextPeriodReset(period, time.Now()).Unix()})
		}
	}
	rows.Close()

	for _, p := range due {
		m.db.Exec("UPDATE rules SET bytes_up = 0, bytes_down = 0, period_reset_at = ? WHERE id = ?", p.next, p.id)
	}
}

func nextPeriodReset(period string, from time.Time) time.Time {
	switch period {
	case "daily":
		return from.AddDate(0, 0, 1)
	case "weekly":
		return from.AddDate(0, 0, 7)
	case "monthly":
		return from.AddDate(0, 1, 0)
	default:
		return time.Time{}
	}
}
