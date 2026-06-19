package main

import (
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    owner           TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    role            TEXT NOT NULL DEFAULT 'local',
    mode            TEXT NOT NULL DEFAULT 'tcp',
    secret          TEXT NOT NULL DEFAULT '',
    host            TEXT NOT NULL DEFAULT '',
    listen_port     INTEGER NOT NULL UNIQUE,
    target_ip       TEXT NOT NULL,
    target_port     INTEGER NOT NULL,
    limit_bytes     INTEGER NOT NULL DEFAULT 0,
    bytes_up        INTEGER NOT NULL DEFAULT 0,
    bytes_down      INTEGER NOT NULL DEFAULT 0,
    period          TEXT NOT NULL DEFAULT 'none',
    period_reset_at INTEGER NOT NULL DEFAULT 0,
    expiry_date     INTEGER NOT NULL DEFAULT 0,
    note            TEXT NOT NULL DEFAULT '',
    active          INTEGER NOT NULL DEFAULT 1,
    created_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rules_owner ON rules(owner);
`

func migrate(db *sql.DB) {
	cols := map[string]string{
		"role":   "TEXT NOT NULL DEFAULT 'local'",
		"mode":   "TEXT NOT NULL DEFAULT 'tcp'",
		"secret": "TEXT NOT NULL DEFAULT ''",
		"host":   "TEXT NOT NULL DEFAULT ''",
	}
	rows, err := db.Query("PRAGMA table_info(rules)")
	if err != nil {
		return
	}
	have := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk)
		have[name] = true
	}
	rows.Close()
	for col, def := range cols {
		if !have[col] {
			db.Exec("ALTER TABLE rules ADD COLUMN " + col + " " + def)
		}
	}
}

func openDB(path string) (*sql.DB, error) {
	dsn := path + "?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // sqlite + WAL: single writer is simplest and avoids "database is locked"
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	migrate(db)
	return db, nil
}

func now() int64 { return time.Now().Unix() }
