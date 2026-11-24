package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	accessTTL  = time.Hour
	refreshTTL = 30 * 24 * time.Hour
	codeTTL    = 5 * time.Minute
)

// Only Claude and ChatGPT may register as OAuth clients.
var allowedRedirectHosts = map[string]bool{
	"claude.ai":           true,
	"claude.com":          true,
	"chatgpt.com":         true,
	"platform.openai.com": true,
}

func redirectAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.User != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	// RFC 8252 loopback redirects for native clients (e.g. Codex CLI): http, IP literal or localhost, any port.
	if u.Scheme == "http" {
		return h == "127.0.0.1" || h == "::1" || h == "localhost"
	}
	return u.Scheme == "https" && allowedRedirectHosts[h]
}

type authServer struct {
	db     *sql.DB
	issuer string

	mu          sync.Mutex
	fails       map[string]*failState
	global      []time.Time
	globalUntil time.Time
}

// credsOK checks username, password and (when enabled) the TOTP code.
// Every check runs, so timing does not reveal which part was wrong.
func (a *authServer) credsOK(user, pw, code string) bool {
	hash := getSetting(a.db, "pw_hash")
	if hash == "" {
		return false
	}
	uOK := subtle.ConstantTimeCompare([]byte(user), []byte(getSetting(a.db, "admin_user"))) == 1
	pOK := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
	tOK := true
	if sec := getSetting(a.db, "totp_secret"); sec != "" {
		tOK = totp.Validate(strings.TrimSpace(code), sec)
	}
	return uOK && pOK && tOK
}

type failState struct {
	n     int
	until time.Time
	last  time.Time
}

func newAuthServer(db *sql.DB, issuer string) *authServer {
	return &authServer{db: db, issuer: strings.TrimRight(issuer, "/"), fails: map[string]*failState{}}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	// Trust X-Forwarded-For only from the local Caddy.
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	return host
}

func (a *authServer) locked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if time.Now().Before(a.globalUntil) {
		return true
	}
	f := a.fails[ip]
	return f != nil && time.Now().Before(f.until)
}

func (a *authServer) recordFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Global throttle: 30 failures in 10 minutes from anywhere pauses all logins for 10 minutes.
	now := time.Now()
	keep := a.global[:0]
	for _, t := range a.global {
		if now.Sub(t) < 10*time.Minute {
			keep = append(keep, t)
		}
	}
	a.global = append(keep, now)
	if len(a.global) >= 30 {
		a.globalUntil = now.Add(10 * time.Minute)
		a.global = nil
	}
	f := a.fails[ip]
	if f == nil {
		f = &failState{}
		a.fails[ip] = f
	}
	if time.Since(f.last) > time.Hour {
		f.n = 0
	}
	f.n++
	f.last = time.Now()
	if f.n >= 5 {
		f.until = time.Now().Add(30 * time.Minute)
		f.n = 0
	}
	if len(a.fails) > 10000 {
		a.fails = map[string]*failState{}
	}
}

func (a *authServer) recordOK(ip string) {
	a.mu.Lock()
	delete(a.fails, ip)
	a.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthErr(w http.ResponseWriter, code int, e, desc string) {
	writeJSON(w, code, map[string]string{"error": e, "error_description": desc})
}

func (a *authServer) routes(mux *http.ServeMux) {
	prm := func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"resource":                 a.issuer + "/mcp",
			"authorization_servers":    []string{a.issuer},
			"bearer_methods_supported": []string{"header"},
		})
	}
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", prm)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", prm)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"issuer":                                a.issuer,
			"authorization_endpoint":                a.issuer + "/authorize",
			"token_endpoint":                        a.issuer + "/token",
			"registration_endpoint":                 a.issuer + "/register",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"none"},
		})
	})
	mux.HandleFunc("POST /register", a.register)
	mux.HandleFunc("GET /authorize", a.authorizeGet)
	mux.HandleFunc("POST /authorize", a.authorizePost)
	mux.HandleFunc("POST /token", a.token)
}

func (a *authServer) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil || len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 10 {
		oauthErr(w, 400, "invalid_client_metadata", "redirect_uris required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !redirectAllowed(u) {
			oauthErr(w, 400, "invalid_redirect_uri", "redirect host not permitted")
			return
		}
	}
	name := req.ClientName
	if len(name) > 100 {
		name = name[:100]
	}
	id := randToken(16)
	uris, _ := json.Marshal(req.RedirectURIs)
	var n int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM oauth_clients`).Scan(&n)
	if n > 200 {
		_, _ = a.db.Exec(`DELETE FROM oauth_clients WHERE created < ?`, time.Now().Add(-30*24*time.Hour).Unix())
	}
	if _, err := a.db.Exec(`INSERT INTO oauth_clients(id,name,redirect_uris,created) VALUES(?,?,?,?)`, id, name, string(uris), time.Now().Unix()); err != nil {
		oauthErr(w, 500, "server_error", "")
		return
	}
	writeJSON(w, 201, map[string]any{
		"client_id":                  id,
		"client_name":                name,
		"redirect_uris":              req.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
}

func (a *authServer) client(id string) (string, []string, bool) {
	var name, raw string
	if err := a.db.QueryRow(`SELECT name,redirect_uris FROM oauth_clients WHERE id=?`, id).Scan(&name, &raw); err != nil {
		return "", nil, false
	}
	var uris []string
	_ = json.Unmarshal([]byte(raw), &uris)
	return name, uris, true
}

var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>sshmcp sign-in</title>
<style>body{font:16px system-ui,sans-serif;max-width:22rem;margin:4rem auto;padding:0 1rem}
input,button{width:100%;box-sizing:border-box;padding:.6rem;margin:.3rem 0 1rem;font:inherit}
.err{color:#b00020}small{color:#555}</style></head><body>
<h1>sshmcp</h1>
<p><small>Authorise <b>{{.Client}}</b> to use your SSH gateway.</small></p>
{{if .Err}}<p class="err">{{.Err}}</p>{{end}}
<form method="post" action="/authorize" autocomplete="off">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
<input type="hidden" name="state" value="{{.State}}">
<input type="hidden" name="code_challenge" value="{{.Challenge}}">
<label>Username<input name="username" autocomplete="username" required autofocus></label>
<label>Password<input type="password" name="password" autocomplete="current-password" required></label>
<label>Authenticator code <small>(only if enabled)</small><input name="totp" inputmode="numeric" maxlength="6"></label>
<button type="submit">Authorise</button></form></body></html>`))

type loginData struct {
	Client, ClientID, RedirectURI, State, Challenge, CSRF, Err string
}

func secHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// validateAuthz checks the client/redirect pair and PKCE parameters.
func (a *authServer) validateAuthz(clientID, redirect, challenge string) (string, string) {
	name, uris, ok := a.client(clientID)
	if !ok {
		return "", "unknown client"
	}
	match := false
	for _, u := range uris {
		if u == redirect {
			match = true
		}
	}
	if !match || !redirectAllowed(redirect) {
		return "", "redirect_uri not registered"
	}
	if len(challenge) < 43 || len(challenge) > 128 {
		return "", "PKCE code_challenge required"
	}
	if name == "" {
		name = "an MCP client"
	}
	return name, ""
}

func (a *authServer) authorizeGet(w http.ResponseWriter, r *http.Request) {
	secHeaders(w)
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "unsupported request", 400)
		return
	}
	name, msg := a.validateAuthz(q.Get("client_id"), q.Get("redirect_uri"), q.Get("code_challenge"))
	if msg != "" {
		http.Error(w, msg, 400)
		return
	}
	if getSetting(a.db, "pw_hash") == "" {
		http.Error(w, "server not configured (run: sshmcp passwd)", 503)
		return
	}
	csrf := randToken(18)
	http.SetCookie(w, &http.Cookie{Name: "csrf", Value: csrf, Path: "/authorize", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTmpl.Execute(w, loginData{name, q.Get("client_id"), q.Get("redirect_uri"), q.Get("state"), q.Get("code_challenge"), csrf, ""})
}

func (a *authServer) authorizePost(w http.ResponseWriter, r *http.Request) {
	secHeaders(w)
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	f := r.PostForm
	c, err := r.Cookie("csrf")
	if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(f.Get("csrf"))) != 1 {
		http.Error(w, "csrf check failed", 403)
		return
	}
	clientID, redirect, challenge, state := f.Get("client_id"), f.Get("redirect_uri"), f.Get("code_challenge"), f.Get("state")
	name, msg := a.validateAuthz(clientID, redirect, challenge)
	if msg != "" {
		http.Error(w, msg, 400)
		return
	}
	ip := clientIP(r)
	rerender := func(code int, e string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(code)
		_ = loginTmpl.Execute(w, loginData{name, clientID, redirect, state, challenge, f.Get("csrf"), e})
	}
	if a.locked(ip) {
		audit(a.db, "login", "", ip, "locked", "")
		rerender(429, "Too many attempts. Try again later.")
		return
	}
	if !a.credsOK(f.Get("username"), f.Get("password"), f.Get("totp")) {
		a.recordFail(ip)
		audit(a.db, "login", "", ip, "failed", "")
		rerender(401, "Invalid credentials.")
		return
	}
	a.recordOK(ip)
	code := randToken(32)
	_, err = a.db.Exec(`INSERT INTO oauth_codes(hash,client_id,redirect_uri,challenge,expires) VALUES(?,?,?,?,?)`,
		hashToken(code), clientID, redirect, challenge, time.Now().Add(codeTTL).Unix())
	if err != nil {
		http.Error(w, "server error", 500)
		return
	}
	audit(a.db, "login", "", ip, "ok client="+name, clientID)
	u, _ := url.Parse(redirect)
	qs := u.Query()
	qs.Set("code", code)
	if state != "" {
		qs.Set("state", state)
	}
	u.RawQuery = qs.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (a *authServer) issue(clientID string) map[string]any {
	at, rt := randToken(32), randToken(32)
	now := time.Now()
	_, _ = a.db.Exec(`INSERT INTO oauth_tokens(hash,kind,client_id,expires) VALUES(?,?,?,?)`, hashToken(at), "access", clientID, now.Add(accessTTL).Unix())
	_, _ = a.db.Exec(`INSERT INTO oauth_tokens(hash,kind,client_id,expires) VALUES(?,?,?,?)`, hashToken(rt), "refresh", clientID, now.Add(refreshTTL).Unix())
	return map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": int(accessTTL.Seconds()), "refresh_token": rt}
}

func (a *authServer) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		oauthErr(w, 400, "invalid_request", "")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		code, verifier := r.PostForm.Get("code"), r.PostForm.Get("code_verifier")
		var clientID, redirect, challenge string
		var exp int64
		tx, err := a.db.Begin()
		if err != nil {
			oauthErr(w, 500, "server_error", "")
			return
		}
		defer tx.Rollback()
		err = tx.QueryRow(`SELECT client_id,redirect_uri,challenge,expires FROM oauth_codes WHERE hash=?`, hashToken(code)).Scan(&clientID, &redirect, &challenge, &exp)
		if err != nil {
			oauthErr(w, 400, "invalid_grant", "unknown code")
			return
		}
		_, _ = tx.Exec(`DELETE FROM oauth_codes WHERE hash=?`, hashToken(code)) // single use
		if err := tx.Commit(); err != nil {
			oauthErr(w, 500, "server_error", "")
			return
		}
		sum := sha256.Sum256([]byte(verifier))
		calc := base64.RawURLEncoding.EncodeToString(sum[:])
		if time.Now().Unix() > exp || subtle.ConstantTimeCompare([]byte(calc), []byte(challenge)) != 1 ||
			r.PostForm.Get("client_id") != clientID || r.PostForm.Get("redirect_uri") != redirect {
			oauthErr(w, 400, "invalid_grant", "verification failed")
			return
		}
		writeJSON(w, 200, a.issue(clientID))
	case "refresh_token":
		rt := r.PostForm.Get("refresh_token")
		var clientID string
		var exp int64
		err := a.db.QueryRow(`SELECT client_id,expires FROM oauth_tokens WHERE hash=? AND kind='refresh'`, hashToken(rt)).Scan(&clientID, &exp)
		if err != nil || time.Now().Unix() > exp {
			oauthErr(w, 400, "invalid_grant", "refresh token invalid")
			return
		}
		if cid := r.PostForm.Get("client_id"); cid != "" && cid != clientID {
			oauthErr(w, 400, "invalid_grant", "client mismatch")
			return
		}
		_, _ = a.db.Exec(`DELETE FROM oauth_tokens WHERE hash=?`, hashToken(rt)) // rotate
		writeJSON(w, 200, a.issue(clientID))
	default:
		oauthErr(w, 400, "unsupported_grant_type", "")
	}
}
