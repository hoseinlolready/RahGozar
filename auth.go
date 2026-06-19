package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"strings"
)

const (
	pbkdf2Iterations = 120000
	saltBytes        = 16
	sessionTTL       = 30 * 24 * 3600 // 30 days, matches the old cookie lifetime
)

// pbkdf2SHA256 derives a key using PBKDF2-HMAC-SHA256.
// Implemented locally so the binary has exactly one external dependency
// (the sqlite driver) and stays trivial to cross-compile.
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var dk []byte
	buf := make([]byte, len(salt)+4)
	copy(buf, salt)

	for block := 1; block <= numBlocks; block++ {
		buf[len(salt)] = byte(block >> 24)
		buf[len(salt)+1] = byte(block >> 16)
		buf[len(salt)+2] = byte(block >> 8)
		buf[len(salt)+3] = byte(block)

		prf.Reset()
		prf.Write(buf)
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)

		for n := 2; n <= iterations; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for i := range t {
				t[i] ^= u[i]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable, fail loudly rather than weaken security
	}
	return hex.EncodeToString(b)
}

// hashPassword returns "salt$hash", both hex-encoded.
func hashPassword(password string) string {
	salt := make([]byte, saltBytes)
	rand.Read(salt)
	hash := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, 32)
	return hex.EncodeToString(salt) + "$" + hex.EncodeToString(hash)
}

func verifyPassword(stored, password string) bool {
	saltHex, hashHex, ok := strings.Cut(stored, "$")
	if !ok {
		return false
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(hashHex)
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func createSession(db *sql.DB, username string) (string, error) {
	token := randomHex(24)
	_, err := db.Exec("INSERT INTO sessions (token, username, created_at) VALUES (?, ?, ?)", token, username, now())
	return token, err
}

func getSessionUser(db *sql.DB, token string) (*User, error) {
	if token == "" {
		return nil, nil
	}
	row := db.QueryRow(`
		SELECT u.username, u.password_hash, u.role, u.created_at
		FROM sessions s JOIN users u ON u.username = s.username
		WHERE s.token = ? AND s.created_at > ?`, token, now()-sessionTTL)

	var u User
	err := row.Scan(&u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func deleteSession(db *sql.DB, token string) {
	db.Exec("DELETE FROM sessions WHERE token = ?", token)
}

func cleanupExpiredSessions(db *sql.DB) {
	db.Exec("DELETE FROM sessions WHERE created_at <= ?", now()-sessionTTL)
}
