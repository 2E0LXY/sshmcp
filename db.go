package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS hosts (
  name     TEXT PRIMARY KEY,
  addr     TEXT NOT NULL,
  port     INTEGER NOT NULL DEFAULT 22,
  user     TEXT NOT NULL,
  auth     TEXT NOT NULL DEFAULT 'password' CHECK (auth IN ('password','key')),
  secret   TEXT NOT NULL,
  host_key TEXT NOT NULL,
  policy   TEXT NOT NULL DEFAULT 'readonly' CHECK (policy IN ('readonly','allowlist','full')),
  allow    TEXT NOT NULL DEFAULT '',
  note     TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_clients (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, redirect_uris TEXT NOT NULL, created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_codes (
  hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
  challenge TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_tokens (
  hash TEXT PRIMARY KEY, kind TEXT NOT NULL, client_id TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, tool TEXT NOT NULL,
  host TEXT NOT NULL, detail TEXT NOT NULL, result TEXT NOT NULL, client TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
`

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return db, nil
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func getSetting(db *sql.DB, k string) string {
	var v string
	_ = db.QueryRow(`SELECT v FROM settings WHERE k=?`, k).Scan(&v)
	return v
}

func setSetting(db *sql.DB, k, v string) error {
	_, err := db.Exec(`INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

func audit(db *sql.DB, tool, host, detail, result, client string) {
	if len(detail) > 2000 {
		detail = detail[:2000] + "…"
	}
	_, _ = db.Exec(`INSERT INTO audit(ts,tool,host,detail,result,client) VALUES(?,?,?,?,?,?)`,
		time.Now().Unix(), tool, host, detail, result, client)
}

func purgeExpired(db *sql.DB) {
	now := time.Now().Unix()
	_, _ = db.Exec(`DELETE FROM oauth_codes WHERE expires < ?`, now)
	_, _ = db.Exec(`DELETE FROM oauth_tokens WHERE expires < ?`, now)
	_, _ = db.Exec(`DELETE FROM sessions WHERE expires < ?`, now)
	_, _ = db.Exec(`DELETE FROM audit WHERE ts < ?`, now-90*86400)
}
