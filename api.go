package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type Server struct {
	db  *sql.DB
	mgr *Manager
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/me", s.handleMe)
	mux.HandleFunc("/api/password", s.requireAuth(s.handlePassword))
	mux.HandleFunc("/api/rules", s.requireAuth(s.handleRules))
	mux.HandleFunc("/api/rules/reset", s.requireAuth(s.handleResetRule))
	mux.HandleFunc("/api/admins", s.requireAuth(s.handleAdmins))
	mux.HandleFunc("/api/stats", s.requireAuth(s.handleStats))
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(panelHTML)
}

func tokenFromRequest(r *http.Request) string {
	c, err := r.Cookie("token")
	if err != nil {
		return ""
	}
	return c.Value
}

func (s *Server) currentUser(r *http.Request) *User {
	u, _ := getSessionUser(s.db, tokenFromRequest(r))
	return u
}

type ctxKey int

const userCtxKey ctxKey = 0

func (s *Server) requireAuth(next func(http.ResponseWriter, *http.Request, *User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := s.currentUser(r)
		if u == nil {
			writeJSON(w, 401, map[string]any{"error": "unauthorized"})
			return
		}
		next(w, r, u)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	if u == nil {
		writeJSON(w, 200, map[string]any{"auth": false})
		return
	}
	writeJSON(w, 200, map[string]any{"auth": true, "username": u.Username, "role": u.Role})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct{ U, P string }
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request"})
		return
	}

	row := s.db.QueryRow("SELECT password_hash FROM users WHERE username = ?", body.U)
	var hash string
	if err := row.Scan(&hash); err != nil || !verifyPassword(hash, body.P) {
		writeJSON(w, 401, map[string]any{"success": false, "error": "invalid credentials"})
		return
	}

	token, err := createSession(s.db, body.U)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "could not create session"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		MaxAge:   sessionTTL,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, 200, map[string]any{"success": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	deleteSession(s.db, tokenFromRequest(r))
	http.SetCookie(w, &http.Cookie{Name: "token", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]any{"success": true})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request, u *User) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, nil)
		return
	}
	var body struct{ Old, New string }
	if err := readJSON(r, &body); err != nil || len(body.New) < 6 {
		writeJSON(w, 400, map[string]any{"error": "new password must be at least 6 characters"})
		return
	}
	if !verifyPassword(u.PasswordHash, body.Old) {
		writeJSON(w, 401, map[string]any{"error": "current password is incorrect"})
		return
	}
	s.db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", hashPassword(body.New), u.Username)
	writeJSON(w, 200, map[string]any{"success": true})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request, u *User) {
	switch r.Method {
	case http.MethodGet:
		s.listRules(w, r, u)
	case http.MethodPost:
		s.createRule(w, r, u)
	case http.MethodPut:
		s.updateRule(w, r, u)
	case http.MethodDelete:
		s.deleteRule(w, r, u)
	default:
		writeJSON(w, 405, nil)
	}
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request, u *User) {
	var rows *sql.Rows
	var err error
	filterOwner := r.URL.Query().Get("admin")

	q := `SELECT id, owner, name, listen_port, target_ip, target_port, limit_bytes,
		bytes_up, bytes_down, period, period_reset_at, expiry_date, note, active, created_at
		FROM rules`

	if u.Role == "owner" {
		if filterOwner != "" {
			rows, err = s.db.Query(q+" WHERE owner = ? ORDER BY created_at DESC", filterOwner)
		} else {
			rows, err = s.db.Query(q + " ORDER BY created_at DESC")
		}
	} else {
		rows, err = s.db.Query(q+" WHERE owner = ? ORDER BY created_at DESC", u.Username)
	}
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	defer rows.Close()

	rules := []Rule{}
	nowTs := now()
	for rows.Next() {
		var rl Rule
		var active int
		if err := rows.Scan(&rl.ID, &rl.Owner, &rl.Name, &rl.ListenPort, &rl.TargetIP, &rl.TargetPort,
			&rl.LimitBytes, &rl.BytesUp, &rl.BytesDown, &rl.Period, &rl.PeriodResetAt, &rl.ExpiryDate,
			&rl.Note, &active, &rl.CreatedAt); err != nil {
			continue
		}
		rl.Active = active == 1
		rl.Status = computeStatus(rl, nowTs)
		rl.RateUpBps, rl.RateDownBps = s.mgr.Rate(rl.ID)
		rules = append(rules, rl)
	}

	writeJSON(w, 200, map[string]any{"rules": rules})
}

func computeStatus(r Rule, nowTs int64) string {
	if !r.Active {
		return "inactive"
	}
	if r.ExpiryDate > 0 && nowTs > r.ExpiryDate {
		return "expired"
	}
	if r.LimitBytes > 0 && (r.BytesUp+r.BytesDown) >= r.LimitBytes {
		return "limited"
	}
	return "active"
}

type ruleInput struct {
	ID         int64   `json:"id"`
	Owner      string  `json:"owner"` // owner only: assign tunnel to a specific admin
	Name       string  `json:"name"`
	ListenPort int     `json:"listen_port"`
	TargetIP   string  `json:"target_ip"`
	TargetPort int     `json:"target_port"`
	LimitGB    float64 `json:"limit_gb"`
	Period     string  `json:"period"`
	Expiry     string  `json:"expiry"` // YYYY-MM-DD
	Note       string  `json:"note"`
	Active     bool    `json:"active"`
}

func parseExpiry(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

func validPeriod(p string) bool {
	switch p {
	case "", "none", "daily", "weekly", "monthly":
		return true
	}
	return false
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request, u *User) {
	var in ruleInput
	if err := readJSON(r, &in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request"})
		return
	}
	if in.ListenPort <= 0 || in.ListenPort > 65535 || in.TargetIP == "" || in.TargetPort <= 0 {
		writeJSON(w, 400, map[string]any{"error": "listen_port, target_ip and target_port are required"})
		return
	}
	if !validPeriod(in.Period) {
		writeJSON(w, 400, map[string]any{"error": "invalid period"})
		return
	}
	expiry, err := parseExpiry(in.Expiry)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid expiry date"})
		return
	}

	owner := u.Username
	if u.Role == "owner" && in.Owner != "" {
		owner = in.Owner
		var exists string
		if err := s.db.QueryRow("SELECT username FROM users WHERE username = ?", owner).Scan(&exists); err != nil {
			writeJSON(w, 400, map[string]any{"error": "target admin does not exist"})
			return
		}
	}

	period := in.Period
	if period == "" {
		period = "none"
	}
	var periodResetAt int64
	if period != "none" {
		periodResetAt = nextPeriodReset(period, time.Now()).Unix()
	}

	limitBytes := int64(in.LimitGB * 1073741824)

	_, err = s.db.Exec(`INSERT INTO rules
		(owner, name, listen_port, target_ip, target_port, limit_bytes, period, period_reset_at, expiry_date, note, active, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		owner, in.Name, in.ListenPort, in.TargetIP, in.TargetPort, limitBytes, period, periodResetAt, expiry, in.Note, boolToInt(in.Active), now())

	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeJSON(w, 409, map[string]any{"error": fmt.Sprintf("port %d is already in use by another tunnel", in.ListenPort)})
			return
		}
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"success": true})
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request, u *User) {
	var in ruleInput
	if err := readJSON(r, &in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request"})
		return
	}

	existingOwner, err := s.ruleOwner(in.ID)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": "tunnel not found"})
		return
	}
	if u.Role != "owner" && existingOwner != u.Username {
		writeJSON(w, 403, map[string]any{"error": "forbidden"})
		return
	}
	if !validPeriod(in.Period) {
		writeJSON(w, 400, map[string]any{"error": "invalid period"})
		return
	}

	var conflict int64
	err = s.db.QueryRow("SELECT id FROM rules WHERE listen_port = ? AND id != ?", in.ListenPort, in.ID).Scan(&conflict)
	if err == nil {
		writeJSON(w, 409, map[string]any{"error": fmt.Sprintf("port %d is already used by another tunnel", in.ListenPort)})
		return
	}

	expiry, err := parseExpiry(in.Expiry)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid expiry date"})
		return
	}

	owner := existingOwner
	if u.Role == "owner" && in.Owner != "" {
		owner = in.Owner
	}

	period := in.Period
	if period == "" {
		period = "none"
	}

	// only reschedule the reset window if the period actually changed
	var curPeriod string
	s.db.QueryRow("SELECT period FROM rules WHERE id = ?", in.ID).Scan(&curPeriod)
	periodResetAtClause := ""
	args := []any{owner, in.Name, in.ListenPort, in.TargetIP, in.TargetPort,
		int64(in.LimitGB * 1073741824), period, expiry, in.Note, boolToInt(in.Active)}

	if period != curPeriod {
		periodResetAtClause = ", period_reset_at = ?"
		if period == "none" {
			args = append(args, 0)
		} else {
			args = append(args, nextPeriodReset(period, time.Now()).Unix())
		}
	}
	args = append(args, in.ID)

	query := fmt.Sprintf(`UPDATE rules SET owner=?, name=?, listen_port=?, target_ip=?, target_port=?,
		limit_bytes=?, period=?, expiry_date=?, note=?, active=?%s WHERE id=?`, periodResetAtClause)

	if _, err := s.db.Exec(query, args...); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"success": true})
}

func (s *Server) ruleOwner(id int64) (string, error) {
	var owner string
	err := s.db.QueryRow("SELECT owner FROM rules WHERE id = ?", id).Scan(&owner)
	return owner, err
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request, u *User) {
	var body struct {
		ID int64 `json:"id"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, 400, nil)
		return
	}
	owner, err := s.ruleOwner(body.ID)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": "not found"})
		return
	}
	if u.Role != "owner" && owner != u.Username {
		writeJSON(w, 403, map[string]any{"error": "forbidden"})
		return
	}
	s.db.Exec("DELETE FROM rules WHERE id = ?", body.ID)
	writeJSON(w, 200, map[string]any{"success": true})
}

func (s *Server) handleResetRule(w http.ResponseWriter, r *http.Request, u *User) {
	var body struct {
		ID int64 `json:"id"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, 400, nil)
		return
	}
	owner, err := s.ruleOwner(body.ID)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": "not found"})
		return
	}
	if u.Role != "owner" && owner != u.Username {
		writeJSON(w, 403, map[string]any{"error": "forbidden"})
		return
	}
	s.db.Exec("UPDATE rules SET bytes_up = 0, bytes_down = 0 WHERE id = ?", body.ID)
	writeJSON(w, 200, map[string]any{"success": true})
}

func (s *Server) handleAdmins(w http.ResponseWriter, r *http.Request, u *User) {
	if u.Role != "owner" {
		writeJSON(w, 403, map[string]any{"error": "owner only"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.Query(`SELECT u.username, u.role, u.created_at,
			(SELECT COUNT(*) FROM rules WHERE owner = u.username) as rule_count
			FROM users u WHERE u.role != 'owner' ORDER BY u.created_at DESC`)
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		defer rows.Close()
		type adminRow struct {
			Username  string `json:"username"`
			Role      string `json:"role"`
			CreatedAt int64  `json:"created_at"`
			RuleCount int    `json:"rule_count"`
		}
		out := []adminRow{}
		for rows.Next() {
			var a adminRow
			rows.Scan(&a.Username, &a.Role, &a.CreatedAt, &a.RuleCount)
			out = append(out, a)
		}
		writeJSON(w, 200, map[string]any{"admins": out})

	case http.MethodPost:
		var body struct{ Username, Password string }
		if err := readJSON(r, &body); err != nil || body.Username == "" || len(body.Password) < 6 {
			writeJSON(w, 400, map[string]any{"error": "username and a password of 6+ characters are required"})
			return
		}
		_, err := s.db.Exec("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
			body.Username, hashPassword(body.Password), now())
		if err != nil {
			writeJSON(w, 409, map[string]any{"error": "that username is already taken"})
			return
		}
		writeJSON(w, 200, map[string]any{"success": true})

	case http.MethodDelete:
		var body struct{ Username string }
		if err := readJSON(r, &body); err != nil {
			writeJSON(w, 400, nil)
			return
		}
		s.db.Exec("DELETE FROM rules WHERE owner = ?", body.Username)
		s.db.Exec("DELETE FROM sessions WHERE username = ?", body.Username)
		s.db.Exec("DELETE FROM users WHERE username = ? AND role != 'owner'", body.Username)
		writeJSON(w, 200, map[string]any{"success": true})

	default:
		writeJSON(w, 405, nil)
	}
}

var processStart = time.Now()

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request, u *User) {
	stats := getSystemStats()

	scope := "WHERE 1=1"
	args := []any{}
	if u.Role != "owner" {
		scope = "WHERE owner = ?"
		args = append(args, u.Username)
	}

	row := s.db.QueryRow(fmt.Sprintf("SELECT COUNT(*), COALESCE(SUM(active),0) FROM rules %s", scope), args...)
	row.Scan(&stats.TotalRules, &stats.ActiveRules)

	// Sum live rates across this user's rules.
	rows, _ := s.db.Query(fmt.Sprintf("SELECT id FROM rules %s AND active = 1", scope), args...)
	if rows != nil {
		for rows.Next() {
			var id int64
			rows.Scan(&id)
			up, down := s.mgr.Rate(id)
			stats.TotalUpBps += up
			stats.TotalDownBps += down
		}
		rows.Close()
	}

	writeJSON(w, 200, stats)
}

func getSystemStats() SysStats {
	s := SysStats{MemText: "N/A", UptimeText: "N/A"}

	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		info := map[string]int64{}
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Fields(strings.Replace(line, ":", "", 1))
			if len(parts) >= 2 {
				var v int64
				fmt.Sscanf(parts[1], "%d", &v)
				info[parts[0]] = v
			}
		}
		total := info["MemTotal"]
		avail := info["MemAvailable"]
		if total > 0 {
			used := total - avail
			s.MemText = fmt.Sprintf("%.2f GB / %.2f GB", float64(used)/1048576, float64(total)/1048576)
			s.MemPercent = int(float64(used) / float64(total) * 100)
		}
	}

	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		var load1 float64
		fmt.Sscanf(string(data), "%f", &load1)
		// crude approximation: load relative to core count, capped at 100%
		ncpu := 1
		if cpuinfo, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			ncpu = strings.Count(string(cpuinfo), "processor")
			if ncpu == 0 {
				ncpu = 1
			}
		}
		pct := int(load1 / float64(ncpu) * 100)
		if pct > 100 {
			pct = 100
		}
		s.CPUPercent = pct
	}

	uptime := time.Since(processStart)
	d := int64(uptime.Hours()) / 24
	h := int64(uptime.Hours()) % 24
	m := int64(uptime.Minutes()) % 60
	if d > 0 {
		s.UptimeText = fmt.Sprintf("%dd %dh %dm", d, h, m)
	} else {
		s.UptimeText = fmt.Sprintf("%dh %dm", h, m)
	}

	return s
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
