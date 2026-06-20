package main

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const defaultDBPath = "rahgozar.db"

func main() {
	log.SetFlags(log.Ltime)
	log.SetPrefix("[RahGozar] ")

	var (
		dbPath = flag.String("db", defaultDBPath, "path to the sqlite database file")
		port   = flag.Int("port", 9090, "panel listen port")
		addAdm = flag.Bool("add-admin", false, "interactively create an admin/owner account, then exit")
		listAd = flag.Bool("list-admins", false, "list accounts, then exit")
		delAdm = flag.String("del-admin", "", "delete the named admin account, then exit")
		icmpSrv = flag.Bool("icmp-server", false, "run a standalone ICMP echo server to test the ICMP transport (needs root)")
		icmpCli = flag.String("icmp-client", "", "ICMP ping test: dial this exit IP, send a probe, measure round-trip (needs root)")
		secret  = flag.String("secret", "", "shared secret for -icmp-server / -icmp-client")
		setDbg  = flag.String("debug", "", "turn debug logging on/off for the running service (on|off), then exit")
	)
	flag.Parse()

	switch {
	case *icmpSrv:
		icmpEchoServer(*secret)
		return
	case *icmpCli != "":
		icmpPingClient(*icmpCli, *secret)
		return
	}

	if *setDbg != "" {
		d, err := openDB(*dbPath)
		if err != nil {
			log.Fatalf("open db: %v", err)
		}
		on := *setDbg == "on" || *setDbg == "true" || *setDbg == "1"
		val := "off"
		if on {
			val = "on"
		}
		if err := setSetting(d, "debug", val); err != nil {
			log.Fatalf("could not set debug: %v", err)
		}
		d.Close()
		log.Printf("debug logging turned %s (takes effect within a couple of seconds)", val)
		return
	}

	db, err := openDB(*dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	switch {
	case *addAdm:
		cliAddAdmin(db)
		return
	case *listAd:
		cliListAdmins(db)
		return
	case *delAdm != "":
		cliDelAdmin(db, *delAdm)
		return
	}

	ensureOwnerExists(db)

	mgr := newManager(db)
	go mgr.Run()

	go func() {
		t := time.NewTicker(6 * time.Hour)
		for range t.C {
			cleanupExpiredSessions(db)
		}
	}()

	srv := &Server{db: db, mgr: mgr}
	addr := fmt.Sprintf("0.0.0.0:%d", *port)

	log.Printf("panel listening on http://%s  (public IP: %s)", addr, publicIP())
	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      srv.routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("http server: %v", err)
	}
}

func ensureOwnerExists(db *sql.DB) {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count > 0 {
		return
	}
	fmt.Println("No accounts found. Let's create the owner account.")
	cliAddAdminWithRole(db, "owner")
}

func cliAddAdmin(db *sql.DB) {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'owner'").Scan(&count)
	role := "admin"
	if count == 0 {
		role = "owner"
		fmt.Println("No owner exists yet; this account will be the owner.")
	}
	cliAddAdminWithRole(db, role)
}

var stdinReader = bufio.NewReader(os.Stdin)

func cliAddAdminWithRole(db *sql.DB, role string) {
	fmt.Print("Username: ")
	username, _ := stdinReader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" {
		fmt.Println("Username cannot be empty.")
		os.Exit(1)
	}

	password := readPassword("Password: ")
	if len(password) < 6 {
		fmt.Println("Password must be at least 6 characters.")
		os.Exit(1)
	}
	confirm := readPassword("Confirm password: ")
	if password != confirm {
		fmt.Println("Passwords do not match.")
		os.Exit(1)
	}

	_, err := db.Exec("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
		username, hashPassword(password), role, now())
	if err != nil {
		fmt.Printf("Could not create account (username may already exist): %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Created %s account '%s'.\n", role, username)
}

func cliListAdmins(db *sql.DB) {
	rows, err := db.Query("SELECT username, role, created_at FROM users ORDER BY role DESC, created_at")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer rows.Close()
	fmt.Printf("%-20s %-8s %s\n", "USERNAME", "ROLE", "CREATED")
	for rows.Next() {
		var u, role string
		var created int64
		rows.Scan(&u, &role, &created)
		fmt.Printf("%-20s %-8s %s\n", u, role, time.Unix(created, 0).Format("2006-01-02"))
	}
}

func cliDelAdmin(db *sql.DB, username string) {
	var role string
	if err := db.QueryRow("SELECT role FROM users WHERE username = ?", username).Scan(&role); err != nil {
		fmt.Printf("No such account: %s\n", username)
		os.Exit(1)
	}
	if role == "owner" {
		fmt.Println("Refusing to delete the owner account.")
		os.Exit(1)
	}
	db.Exec("DELETE FROM rules WHERE owner = ?", username)
	db.Exec("DELETE FROM sessions WHERE username = ?", username)
	db.Exec("DELETE FROM users WHERE username = ?", username)
	fmt.Printf("Deleted admin '%s' and all their tunnels.\n", username)
}

func readPassword(prompt string) string {
	fmt.Print(prompt)
	disabled := false
	if _, err := exec.LookPath("stty"); err == nil {
		c := exec.Command("stty", "-echo")
		c.Stdin = os.Stdin
		if c.Run() == nil {
			disabled = true
		}
	}
	line, _ := stdinReader.ReadString('\n')
	if disabled {
		c := exec.Command("stty", "echo")
		c.Stdin = os.Stdin
		c.Run()
		fmt.Println()
	}
	return strings.TrimSpace(line)
}

func publicIP() string {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "127.0.0.1"
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "127.0.0.1"
	}
	return string(body)
}
