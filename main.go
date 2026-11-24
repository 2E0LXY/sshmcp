package main

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

var version = "dev"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sshmcp serve | passwd [--user NAME] [--temp] | totp [--force] | addhost --name N --addr A --user U --fingerprint SHA256:.. [--port 22] [--policy full] [--note ..] (secret on stdin) | version")
		os.Exit(2)
	}
	if os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	dir := env("SSHMCP_DIR", "/var/lib/sshmcp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Fatal(err)
	}
	db, err := openDB(dir + "/sshmcp.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	vault, err = loadVault(dir + "/master.key")
	if err != nil {
		log.Fatal(err)
	}
	switch os.Args[1] {
	case "serve":
		serve(db)
	case "passwd":
		cmdPasswd(db, os.Args[2:])
	case "totp":
		cmdTOTP(db, len(os.Args) > 2 && os.Args[2] == "--force")
	case "addhost":
		cmdAddHost(db, os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}

func readSecret(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			log.Fatal(err)
		}
		return string(b)
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func cmdPasswd(db *sql.DB, args []string) {
	user, temp := "", false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--user":
			i++
			if i < len(args) {
				user = args[i]
			}
		case "--temp":
			temp = true
		}
	}
	pw := readSecret("New admin password (min 12 chars): ")
	if !temp && len(pw) < 12 {
		log.Fatal("password too short (use --temp to seed a short one, then change it in the dashboard)")
	}
	if len(pw) < 1 || len(pw) > 72 {
		log.Fatal("password must be 1-72 bytes")
	}
	if term.IsTerminal(int(os.Stdin.Fd())) && readSecret("Repeat: ") != pw {
		log.Fatal("passwords differ")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	if err != nil {
		log.Fatal(err)
	}
	if err := setSetting(db, "pw_hash", string(h)); err != nil {
		log.Fatal(err)
	}
	if user != "" {
		_ = setSetting(db, "admin_user", user)
	} else if getSetting(db, "admin_user") == "" {
		_ = setSetting(db, "admin_user", "admin")
	}
	if temp || len(pw) < 12 {
		_ = setSetting(db, "pw_temp", "1")
	} else {
		_ = setSetting(db, "pw_temp", "0")
	}
	fmt.Println("password set for user", getSetting(db, "admin_user"))
}

func cmdTOTP(db *sql.DB, force bool) {
	if getSetting(db, "totp_secret") != "" && !force {
		log.Fatal("TOTP already configured (use --force to replace)")
	}
	k, err := totp.Generate(totp.GenerateOpts{Issuer: "sshmcp", AccountName: "admin"})
	if err != nil {
		log.Fatal(err)
	}
	if err := setSetting(db, "totp_secret", k.Secret()); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Add to your authenticator app:")
	fmt.Println("  secret:", k.Secret())
	fmt.Println("  uri:   ", k.URL())
}

func bearer(db *sql.DB, issuer string, next http.Handler) http.Handler {
	challenge := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, issuer)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" || tok == r.Header.Get("Authorization") {
			w.Header().Set("WWW-Authenticate", challenge)
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}
		var clientID string
		var exp int64
		err := db.QueryRow(`SELECT client_id,expires FROM oauth_tokens WHERE hash=? AND kind='access'`, hashToken(tok)).Scan(&clientID, &exp)
		if err != nil || time.Now().Unix() > exp {
			w.Header().Set("WWW-Authenticate", challenge+`, error="invalid_token"`)
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientKey, clientID)))
	})
}

func serve(db *sql.DB) {
	issuer := strings.TrimRight(env("SSHMCP_ISSUER", ""), "/")
	if !strings.HasPrefix(issuer, "https://") {
		log.Fatal("SSHMCP_ISSUER must be the public https URL, e.g. https://mcp.example.com")
	}
	addr := env("SSHMCP_ADDR", "127.0.0.1:8765")

	iu, err := url.Parse(issuer)
	if err != nil || iu.Host == "" {
		log.Fatal("bad SSHMCP_ISSUER")
	}
	mcpHandler := newMCPHandler(db, iu.Host)

	a := newAuthServer(db, issuer)
	ad := newAdmin(db, a)
	mux := http.NewServeMux()
	a.routes(mux)
	ad.routes(mux)
	mux.Handle("/mcp", bearer(db, issuer, mcpHandler))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	hs := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	go func() {
		for {
			purgeExpired(db)
			time.Sleep(10 * time.Minute)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
	}()
	log.Printf("sshmcp %s listening on %s (issuer %s)", version, addr, issuer)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// newMCPHandler builds the MCP endpoint. The SDK's localhost-only Host check would
// reject the public hostname behind Caddy, so it is disabled and replaced by an
// exact match on the configured issuer host.
func newMCPHandler(db *sql.DB, host string) http.Handler {
	srv := mcp.NewServer(&mcp.Implementation{Name: "sshmcp", Version: version}, nil)
	registerTools(srv, db)
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true, DisableLocalhostProtection: true})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != host {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}
