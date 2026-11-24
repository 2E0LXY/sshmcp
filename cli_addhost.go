package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// cmdAddHost adds a password-auth host from the command line. The password is
// read from stdin (never argv) and the scanned host key must match the
// fingerprint supplied by the operator, obtained over a separate trusted channel.
func cmdAddHost(db *sql.DB, args []string) {
	h := Host{Port: 22, Policy: "full", Auth: "password"}
	fp := ""
	for i := 0; i+1 < len(args); i += 2 {
		v := args[i+1]
		switch args[i] {
		case "--name":
			h.Name = v
		case "--addr":
			h.Addr = v
		case "--user":
			h.User = v
		case "--port":
			h.Port, _ = strconv.Atoi(v)
		case "--policy":
			h.Policy = v
		case "--note":
			h.Note = v
		case "--fingerprint":
			fp = v
		default:
			log.Fatalf("unknown flag %s", args[i])
		}
	}
	if !reName.MatchString(h.Name) || !reUser.MatchString(h.User) || h.Port < 1 || h.Port > 65535 || !validPolicy(h.Policy) || h.Addr == "" || fp == "" {
		log.Fatal("need valid --name --addr --user --fingerprint (and optional --port --policy --note)")
	}
	secret := readSecret("")
	if secret == "" {
		log.Fatal("empty password on stdin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	key, err := scanHostKey(ctx, h.Addr, h.Port)
	if err != nil {
		log.Fatal("scan: ", err)
	}
	if got := ssh.FingerprintSHA256(key); got != fp {
		log.Fatalf("host key mismatch: server presented %s, expected %s", got, fp)
	}
	h.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if h.Secret, err = vault.Seal(secret); err != nil {
		log.Fatal(err)
	}
	res, err := h.exec(ctx, "echo sshmcp-ok", 15*time.Second)
	if err != nil || !strings.Contains(res.Stdout, "sshmcp-ok") {
		audit(db, "host_add", h.Name, h.Addr, "cli login test failed", "cli")
		log.Fatalf("login test failed: %v", err)
	}
	if _, err = db.Exec(`INSERT INTO hosts(name,addr,port,user,auth,secret,host_key,policy,allow,note) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		h.Name, h.Addr, h.Port, h.User, h.Auth, h.Secret, h.HostKey, h.Policy, "", h.Note); err != nil {
		log.Fatal(err)
	}
	audit(db, "host_add", h.Name, fmt.Sprintf("%s:%d policy=%s", h.Addr, h.Port, h.Policy), "ok (cli)", "cli")
	fmt.Println("added", h.Name)
	_ = os.Stdout.Sync()
}
