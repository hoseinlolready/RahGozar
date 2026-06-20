package main

import (
	"database/sql"
	"strconv"
)

func getSetting(db *sql.DB, key, def string) string {
	var v string
	err := db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&v)
	if err != nil {
		return def
	}
	return v
}

func setSetting(db *sql.DB, key, value string) error {
	_, err := db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func getUsageRatio(db *sql.DB) float64 {
	v := getSetting(db, "usage_ratio", "1")
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 {
		return 1
	}
	return f
}

func getAdminContact(db *sql.DB) string {
	return getSetting(db, "admin_contact", "")
}

// adminUsage returns the raw total bytes (up+down) across all of an admin's
// tunnels, before the usage ratio is applied.
func adminUsage(db *sql.DB, username string) int64 {
	var total sql.NullInt64
	db.QueryRow("SELECT COALESCE(SUM(bytes_up + bytes_down), 0) FROM rules WHERE owner = ?", username).Scan(&total)
	return total.Int64
}

// suspendInfo describes why (if at all) an admin account is suspended.
type suspendInfo struct {
	Suspended bool   `json:"suspended"`
	Reason    string `json:"reason"` // "expired" | "limit" | ""
}

// adminSuspended decides whether a specific user is currently suspended, given
// the usage ratio. Owners are never suspended.
func adminSuspended(db *sql.DB, username, role string, ratio float64) suspendInfo {
	if role == "owner" {
		return suspendInfo{}
	}
	var limitBytes, expiry int64
	if err := db.QueryRow("SELECT limit_bytes, expiry_date FROM users WHERE username = ?", username).
		Scan(&limitBytes, &expiry); err != nil {
		return suspendInfo{}
	}
	if expiry > 0 && now() > expiry {
		return suspendInfo{Suspended: true, Reason: "expired"}
	}
	if limitBytes > 0 {
		used := int64(float64(adminUsage(db, username)) * ratio)
		if used >= limitBytes {
			return suspendInfo{Suspended: true, Reason: "limit"}
		}
	}
	return suspendInfo{}
}

// suspendedOwners returns the set of admin usernames currently suspended, so
// the tunnel manager can refuse to run their tunnels.
func suspendedOwners(db *sql.DB, ratio float64) map[string]bool {
	out := map[string]bool{}
	rows, err := db.Query(`SELECT u.username, u.limit_bytes, u.expiry_date,
		COALESCE((SELECT SUM(bytes_up + bytes_down) FROM rules WHERE owner = u.username), 0)
		FROM users u WHERE u.role != 'owner'`)
	if err != nil {
		return out
	}
	defer rows.Close()
	nowTs := now()
	for rows.Next() {
		var name string
		var limitBytes, expiry, used int64
		if err := rows.Scan(&name, &limitBytes, &expiry, &used); err != nil {
			continue
		}
		if expiry > 0 && nowTs > expiry {
			out[name] = true
			continue
		}
		if limitBytes > 0 && int64(float64(used)*ratio) >= limitBytes {
			out[name] = true
		}
	}
	return out
}
