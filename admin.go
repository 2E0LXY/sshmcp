package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

const sessionTTL = 12 * time.Hour

var (
	reName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,39}$`)
	reUser = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,32}$`)
	reHost = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
)

type pendingHost struct {
	h       Host
	secret  string // plaintext, held in memory only until confirmed
	fp      string
	session string
	expires time.Time
}

type admin struct {
	db   *sql.DB
	auth *authServer
	mu   sync.Mutex
	pend map[string]*pendingHost
}

func newAdmin(db *sql.DB, a *authServer) *admin {
	return &admin{db: db, auth: a, pend: map[string]*pendingHost{}}
}

// ---- sessions ----

func (ad *admin) newSession(w http.ResponseWriter) {
	tok, csrf := randToken(32), randToken(18)
	_, _ = ad.db.Exec(`INSERT INTO sessions(hash,csrf,expires) VALUES(?,?,?)`, hashToken(tok), csrf, time.Now().Add(sessionTTL).Unix())
	http.SetCookie(w, &http.Cookie{Name: "sshmcp_sess", Value: tok, Path: "/admin", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
}

func (ad *admin) session(r *http.Request) (csrf, key string, ok bool) {
	c, err := r.Cookie("sshmcp_sess")
	if err != nil {
		return "", "", false
	}
	var exp int64
	h := hashToken(c.Value)
	if err := ad.db.QueryRow(`SELECT csrf,expires FROM sessions WHERE hash=?`, h).Scan(&csrf, &exp); err != nil || time.Now().Unix() > exp {
		return "", "", false
	}
	return csrf, h, true
}

// guard wraps POST handlers: valid session + CSRF token.
func (ad *admin) guard(fn func(w http.ResponseWriter, r *http.Request, sess string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secHeaders(w)
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		csrf, sess, ok := ad.session(r)
		if !ok {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		if err := r.ParseForm(); err != nil || subtle.ConstantTimeCompare([]byte(csrf), []byte(r.PostForm.Get("csrf"))) != 1 {
			http.Error(w, "csrf check failed", 403)
			return
		}
		fn(w, r, sess)
	}
}

func (ad *admin) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin", ad.dashboard)
	mux.HandleFunc("POST /admin/login", ad.login)
	mux.HandleFunc("POST /admin/logout", ad.guard(ad.logout))
	mux.HandleFunc("POST /admin/hosts/new", ad.guard(ad.hostNew))
	mux.HandleFunc("POST /admin/hosts/confirm", ad.guard(ad.hostConfirm))
	mux.HandleFunc("POST /admin/hosts/delete", ad.guard(ad.hostDelete))
	mux.HandleFunc("POST /admin/hosts/policy", ad.guard(ad.hostPolicy))
	mux.HandleFunc("POST /admin/clients/revoke", ad.guard(ad.clientRevoke))
	mux.HandleFunc("POST /admin/tokens/new", ad.guard(ad.tokenNew))
	mux.HandleFunc("POST /admin/account/password", ad.guard(ad.accPassword))
	mux.HandleFunc("POST /admin/account/username", ad.guard(ad.accUsername))
	mux.HandleFunc("POST /admin/account/totp/start", ad.guard(ad.totpStart))
	mux.HandleFunc("POST /admin/account/totp/enable", ad.guard(ad.totpEnable))
	mux.HandleFunc("POST /admin/account/totp/disable", ad.guard(ad.totpDisable))
}

// ---- pages ----

var pageTmpl = template.Must(template.New("p").Parse(`<!doctype html>
<html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>sshmcp</title>
<style>
body{font:15px system-ui,sans-serif;max-width:60rem;margin:1.5rem auto;padding:0 1rem;color:#111}
h1,h2{margin:.6rem 0}table{border-collapse:collapse;width:100%;margin:.5rem 0}
th,td{border-bottom:1px solid #ddd;padding:.4rem;text-align:left;vertical-align:top;font-size:14px}
input,select,textarea,button{font:inherit;padding:.45rem;margin:.15rem 0;box-sizing:border-box}
input,select,textarea{width:100%}button{cursor:pointer}.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(12rem,1fr));gap:.6rem}
.err{color:#b00020}.ok{color:#0a6b2d}code{background:#f3f3f3;padding:.1rem .3rem;word-break:break-all}
.inline{display:inline}.danger{color:#b00020}.card{border:1px solid #ddd;border-radius:6px;padding:.8rem;margin:.8rem 0}
</style></head><body>
<div style="display:flex;justify-content:space-between;align-items:center"><h1>sshmcp</h1>
{{if .CSRF}}<form class="inline" method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Sign out</button></form>{{end}}</div>
{{if .Msg}}<p class="ok">{{.Msg}}</p>{{end}}{{if .Err}}<p class="err">{{.Err}}</p>{{end}}

{{if eq .View "login"}}
<div class="card" style="max-width:22rem"><h2>Sign in</h2>
<form method="post" action="/admin/login" autocomplete="off">
<label>Username<input name="username" autocomplete="username" required autofocus></label>
<label>Password<input type="password" name="password" autocomplete="current-password" required></label>
<label>Authenticator code <small>(only if enabled)</small><input name="totp" inputmode="numeric" maxlength="6"></label>
<button>Sign in</button></form></div>

{{else if eq .View "confirm"}}
<div class="card"><h2>Verify host key</h2>
<p>Server <b>{{.P.h.Name}}</b> ({{.P.h.Addr}}:{{.P.h.Port}}) presented this key. Compare it with the one on the server
(<code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>). It is pinned; later changes are refused.</p>
<p><code>{{.P.fp}}</code></p>
<form method="post" action="/admin/hosts/confirm"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="id" value="{{.ID}}">
<button>Trust key, test login and save</button></form></div>

{{else}}
{{if .TempPW}}<p class="err"><b>Temporary password in use.</b> It was shared in chat. Change it under Account below now{{if not .TOTPOn}}, then enable an authenticator code{{end}}.</p>{{end}}
<h2>Servers</h2>
<table><tr><th>Name</th><th>Address</th><th>User</th><th>Auth</th><th>Policy</th><th></th></tr>
{{range .Hosts}}<tr><td>{{.Name}}<br><small>{{.Note}}</small></td><td>{{.Addr}}:{{.Port}}</td><td>{{.User}}</td><td>{{.Auth}}</td>
<td><form class="inline" method="post" action="/admin/hosts/policy"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="name" value="{{.Name}}">
<select name="policy" style="width:auto" onchange="this.form.submit()">
<option value="readonly" {{if eq .Policy "readonly"}}selected{{end}}>read-only</option>
<option value="allowlist" {{if eq .Policy "allowlist"}}selected{{end}}>allowlist</option>
<option value="full" {{if eq .Policy "full"}}selected{{end}}>full</option></select><br>
<textarea name="allow" rows="2" placeholder="allowlist regexes, one per line" style="margin-top:.3rem">{{.Allow}}</textarea>
<noscript><button>Save</button></noscript></form></td>
<td><form class="inline" method="post" action="/admin/hosts/delete" onsubmit="return confirm('Remove {{.Name}}?')"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="name" value="{{.Name}}"><button class="danger">Remove</button></form></td></tr>
{{else}}<tr><td colspan="6">No servers yet.</td></tr>{{end}}</table>

<div class="card" id="add"><h2>Add server</h2>
<form method="post" action="/admin/hosts/new" autocomplete="off">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<div class="row">
<label>Name<input name="name" value="{{.F.name}}" placeholder="web1" required pattern="[a-z0-9][a-z0-9._-]{0,39}"></label>
<label>IP or hostname<input name="addr" value="{{.F.addr}}" required></label>
<label>Port<input name="port" type="number" value="{{.F.port}}" min="1" max="65535" required></label>
<label>Username<input name="user" value="{{.F.user}}" required></label></div>
<div class="row">
<label>Auth<select name="auth"><option value="password">Password</option><option value="key">Private key</option></select></label>
<label>Policy<select name="policy"><option value="full">Full</option><option value="allowlist">Allowlist</option><option value="readonly">Read-only</option></select></label>
<label>Note<input name="note" maxlength="200"></label></div>
<label>Password or private key (PEM)<textarea name="secret" rows="3" required></textarea></label>
<label>Allowlist regexes (allowlist policy only, one per line)<textarea name="allow" rows="2"></textarea></label>
<button>Fetch host key</button></form></div>

<h2>Account</h2>
<div class="card">
<form method="post" action="/admin/account/password" autocomplete="off"><input type="hidden" name="csrf" value="{{.CSRF}}">
<b>Change password</b> (signed in as <code>{{.AdminUser}}</code>). Signs out other sessions and revokes connected AI clients, which then re-authorise.
<div class="row"><label>Current password<input type="password" name="current" autocomplete="current-password" required></label>
<label>New password (12+ chars)<input type="password" name="new" autocomplete="new-password" minlength="12" required></label>
<label>Repeat<input type="password" name="repeat" autocomplete="new-password" minlength="12" required></label></div>
<button>Change password</button></form>
<hr>
<form method="post" action="/admin/account/username" autocomplete="off"><input type="hidden" name="csrf" value="{{.CSRF}}">
<b>Change username</b>
<div class="row"><label>New username<input name="username" required pattern="[A-Za-z0-9._-]{3,32}"></label>
<label>Current password<input type="password" name="current" required></label></div>
<button>Change username</button></form>
<hr>
<b>Authenticator code (optional): {{if .TOTPOn}}<span class="ok">on</span>{{else}}off{{end}}</b>
{{if .PendingSecret}}
<p>Add this to your authenticator app, then enter a code to switch it on.<br>Secret: <code>{{.PendingSecret}}</code><br>URI: <code>{{.PendingURI}}</code></p>
<form method="post" action="/admin/account/totp/enable"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Code<input name="code" inputmode="numeric" maxlength="6" required></label><button>Enable</button></form>
{{else if .TOTPOn}}
<form method="post" action="/admin/account/totp/disable"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Current password<input type="password" name="current" required></label><button class="danger">Disable</button></form>
{{else}}
<form method="post" action="/admin/account/totp/start"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>Set up</button></form>
{{end}}
</div>

<h2>Connected AI clients</h2>
<table><tr><th>Client</th><th>Registered</th><th></th></tr>
{{range .Clients}}<tr><td>{{.Name}}<br><small>{{.ID}}</small></td><td>{{.Created}}</td>
<td><form class="inline" method="post" action="/admin/clients/revoke"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.ID}}"><button class="danger">Revoke</button></form></td></tr>
{{else}}<tr><td colspan="3">None yet. Add <code>{{.Issuer}}/mcp</code> as a custom connector in Claude or ChatGPT.</td></tr>{{end}}</table>

<h2>API tokens</h2>
{{if .NewToken}}<div class="card"><b>Copy this token now. It is shown once.</b><br><code>{{.NewToken}}</code><br><br>Or, for clients that only accept a URL (no auth needed):<br><code>{{.Issuer}}/mcp/{{.NewToken}}</code></div>{{end}}
<form method="post" action="/admin/tokens/new"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Label<input name="label" placeholder="codex" maxlength="40" required pattern="[A-Za-z0-9 ._-]+"></label><button>Create token</button></form>
<p><small>Use as <code>Authorization: Bearer TOKEN</code> on <code>{{.Issuer}}/mcp</code>. Listed above as "API token"; revoke there.</small></p>

<h2>Audit log (latest 100)</h2>
<table><tr><th>Time (UTC)</th><th>Tool</th><th>Host</th><th>Detail</th><th>Result</th></tr>
{{range .Audit}}<tr><td>{{.TS}}</td><td>{{.Tool}}</td><td>{{.Host}}</td><td><code>{{.Detail}}</code></td><td>{{.Result}}</td></tr>{{end}}</table>
{{end}}
</body></html>`))

type clientRow struct{ ID, Name, Created string }
type auditRow struct{ TS, Tool, Host, Detail, Result string }
type pageData struct {
	F                                map[string]string
	TempPW, TOTPOn                   bool
	AdminUser, PendingSecret         string
	PendingURI                       string
	View, CSRF, Msg, Err, ID, Issuer string
	NewToken                         string
	Hosts                            []Host
	Clients                          []clientRow
	Audit                            []auditRow
	P                                map[string]any
}

func (ad *admin) render(w http.ResponseWriter, code int, d pageData) {
	secHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = pageTmpl.Execute(w, d)
}

func (ad *admin) dashboardData(csrf, msg, errMsg string) pageData {
	d := pageData{View: "dash", CSRF: csrf, Msg: msg, Err: errMsg, Issuer: ad.auth.issuer,
		TempPW: getSetting(ad.db, "pw_temp") == "1", TOTPOn: getSetting(ad.db, "totp_secret") != "",
		AdminUser: getSetting(ad.db, "admin_user")}
	if sec := getSetting(ad.db, "totp_pending"); sec != "" && !d.TOTPOn {
		d.PendingSecret = sec
		d.PendingURI = fmt.Sprintf("otpauth://totp/sshmcp:%s?secret=%s&issuer=sshmcp", d.AdminUser, sec)
	}
	d.Hosts, _ = listHosts(ad.db)
	if rows, err := ad.db.Query(`SELECT id,name,created FROM oauth_clients ORDER BY created DESC LIMIT 50`); err == nil {
		for rows.Next() {
			var c clientRow
			var ts int64
			if rows.Scan(&c.ID, &c.Name, &ts) == nil {
				c.Created = time.Unix(ts, 0).UTC().Format("2006-01-02 15:04")
				d.Clients = append(d.Clients, c)
			}
		}
		rows.Close()
	}
	if rows, err := ad.db.Query(`SELECT ts,tool,host,detail,result FROM audit ORDER BY id DESC LIMIT 100`); err == nil {
		for rows.Next() {
			var a auditRow
			var ts int64
			if rows.Scan(&ts, &a.Tool, &a.Host, &a.Detail, &a.Result) == nil {
				a.TS = time.Unix(ts, 0).UTC().Format("01-02 15:04:05")
				d.Audit = append(d.Audit, a)
			}
		}
		rows.Close()
	}
	return d
}

func (ad *admin) dashboard(w http.ResponseWriter, r *http.Request) {
	csrf, _, ok := ad.session(r)
	if !ok {
		ad.render(w, 200, pageData{View: "login"})
		return
	}
	q := r.URL.Query()
	d := ad.dashboardData(csrf, q.Get("m"), q.Get("e"))
	d.F = map[string]string{"name": q.Get("name"), "addr": q.Get("addr"), "port": q.Get("port"), "user": q.Get("user")}
	if d.F["port"] == "" {
		d.F["port"] = "22"
	}
	ad.render(w, 200, d)
}

func (ad *admin) login(w http.ResponseWriter, r *http.Request) {
	secHeaders(w)
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	// Origin check: the login POST must come from our own site.
	if o := r.Header.Get("Origin"); o != "" && o != ad.auth.issuer {
		http.Error(w, "bad origin", 403)
		return
	}
	ip := clientIP(r)
	if ad.auth.locked(ip) {
		audit(ad.db, "admin_login", "", ip, "locked", "")
		ad.render(w, 429, pageData{View: "login", Err: "Too many attempts. Try again later."})
		return
	}
	if !ad.auth.credsOK(r.PostForm.Get("username"), r.PostForm.Get("password"), r.PostForm.Get("totp")) {
		ad.auth.recordFail(ip)
		audit(ad.db, "admin_login", "", ip, "failed", "")
		ad.render(w, 401, pageData{View: "login", Err: "Invalid credentials."})
		return
	}
	ad.auth.recordOK(ip)
	audit(ad.db, "admin_login", "", ip, "ok", "")
	ad.newSession(w)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (ad *admin) logout(w http.ResponseWriter, r *http.Request, sess string) {
	_, _ = ad.db.Exec(`DELETE FROM sessions WHERE hash=?`, sess)
	http.SetCookie(w, &http.Cookie{Name: "sshmcp_sess", Value: "", Path: "/admin", MaxAge: -1})
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func back(w http.ResponseWriter, r *http.Request, msg, e string) {
	u := "/admin"
	if msg != "" {
		u += "?m=" + urlEsc(msg)
	} else if e != "" {
		u += "?e=" + urlEsc(e)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

func urlEsc(s string) string {
	return strings.NewReplacer(" ", "%20", "&", "%26", "#", "%23", "?", "%3F", "+", "%2B").Replace(s)
}

func validPolicy(p string) bool { return p == "readonly" || p == "allowlist" || p == "full" }

func cleanAllow(raw string) (string, error) {
	var out []string
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if _, err := regexp.Compile("^(?:" + l + ")$"); err != nil {
			return "", fmt.Errorf("bad regex %q: %v", l, err)
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n"), nil
}

// scanHostKey fetches the server's host key and aborts before any credential is sent.
func scanHostKey(ctx context.Context, addr string, port int) (ssh.PublicKey, error) {
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "probe",
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			got = k
			return errors.New("captured")
		},
		HostKeyAlgorithms: scanAlgs,
		Timeout:           dialTimeout,
	}
	target := net.JoinHostPort(addr, strconv.Itoa(port))
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_, _, _, _ = ssh.NewClientConn(conn, target, cfg)
	if got == nil {
		return nil, errors.New("no host key received (is this an SSH server?)")
	}
	return got, nil
}

func (ad *admin) hostNew(w http.ResponseWriter, r *http.Request, sess string) {
	f := r.PostForm
	h := Host{
		Name: strings.TrimSpace(f.Get("name")), Addr: strings.TrimSpace(f.Get("addr")),
		User: strings.TrimSpace(f.Get("user")), Auth: f.Get("auth"), Policy: f.Get("policy"),
		Note: strings.TrimSpace(f.Get("note")),
	}
	port, _ := strconv.Atoi(f.Get("port"))
	h.Port = port
	secret := f.Get("secret")
	if h.Auth == "key" {
		secret = strings.TrimSpace(strings.ReplaceAll(secret, "\r\n", "\n")) + "\n"
	}
	switch {
	case !reName.MatchString(h.Name):
		back(w, r, "", "Invalid name (lowercase letters, digits, . _ -)")
		return
	case !reHost.MatchString(h.Addr) && net.ParseIP(h.Addr) == nil:
		back(w, r, "", "Invalid address")
		return
	case h.Port < 1 || h.Port > 65535:
		back(w, r, "", "Invalid port")
		return
	case !reUser.MatchString(h.User):
		back(w, r, "", "Invalid username")
		return
	case h.Auth != "password" && h.Auth != "key":
		back(w, r, "", "Invalid auth type")
		return
	case !validPolicy(h.Policy):
		back(w, r, "", "Invalid policy")
		return
	case strings.TrimSpace(secret) == "":
		back(w, r, "", "Password or key required")
		return
	case len(secret) > 16<<10:
		back(w, r, "", "Secret too long")
		return
	}
	if h.Auth == "key" {
		if _, err := ssh.ParsePrivateKey([]byte(secret)); err != nil {
			back(w, r, "", "Private key not usable (passphrase-protected keys are not supported)")
			return
		}
	}
	var exists int
	_ = ad.db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE name=?`, h.Name).Scan(&exists)
	if exists > 0 {
		back(w, r, "", "A server with that name already exists")
		return
	}
	allow, err := cleanAllow(f.Get("allow"))
	if err != nil {
		back(w, r, "", err.Error())
		return
	}
	h.Allow = allow
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	key, err := scanHostKey(ctx, h.Addr, h.Port)
	if err != nil {
		back(w, r, "", "Cannot reach host: "+err.Error())
		return
	}
	h.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	id := randToken(16)
	ad.mu.Lock()
	for k, p := range ad.pend {
		if time.Now().After(p.expires) {
			delete(ad.pend, k)
		}
	}
	ad.pend[id] = &pendingHost{h: h, secret: secret, fp: ssh.FingerprintSHA256(key) + " (" + key.Type() + ")", session: sess, expires: time.Now().Add(10 * time.Minute)}
	ad.mu.Unlock()
	csrf, _, _ := ad.session(r)
	ad.render(w, 200, pageData{View: "confirm", CSRF: csrf, ID: id, P: map[string]any{"h": h, "fp": ad.pend[id].fp}})
}

func (ad *admin) hostConfirm(w http.ResponseWriter, r *http.Request, sess string) {
	id := r.PostForm.Get("id")
	ad.mu.Lock()
	p, ok := ad.pend[id]
	if ok {
		delete(ad.pend, id)
	}
	ad.mu.Unlock()
	if !ok || p.session != sess || time.Now().After(p.expires) {
		back(w, r, "", "Request expired, start again")
		return
	}
	enc, err := vault.Seal(p.secret)
	if err != nil {
		back(w, r, "", "Encryption failed")
		return
	}
	h := p.h
	h.Secret = enc
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, err := h.exec(ctx, "echo sshmcp-ok", 15*time.Second)
	if err != nil || !strings.Contains(res.Stdout, "sshmcp-ok") {
		msg := "login failed"
		if err != nil {
			msg = err.Error()
		}
		audit(ad.db, "host_add", h.Name, h.Addr, "login test failed", "admin")
		back(w, r, "", "Not saved, login test failed: "+msg)
		return
	}
	_, err = ad.db.Exec(`INSERT INTO hosts(name,addr,port,user,auth,secret,host_key,policy,allow,note) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		h.Name, h.Addr, h.Port, h.User, h.Auth, h.Secret, h.HostKey, h.Policy, h.Allow, h.Note)
	if err != nil {
		back(w, r, "", "Could not save: "+err.Error())
		return
	}
	audit(ad.db, "host_add", h.Name, fmt.Sprintf("%s:%d policy=%s", h.Addr, h.Port, h.Policy), "ok", "admin")
	back(w, r, "Added "+h.Name, "")
}

func (ad *admin) hostDelete(w http.ResponseWriter, r *http.Request, _ string) {
	name := r.PostForm.Get("name")
	_, _ = ad.db.Exec(`DELETE FROM hosts WHERE name=?`, name)
	audit(ad.db, "host_remove", name, "", "ok", "admin")
	back(w, r, "Removed "+name, "")
}

func (ad *admin) hostPolicy(w http.ResponseWriter, r *http.Request, _ string) {
	name, pol := r.PostForm.Get("name"), r.PostForm.Get("policy")
	if !validPolicy(pol) {
		back(w, r, "", "Invalid policy")
		return
	}
	allow, err := cleanAllow(r.PostForm.Get("allow"))
	if err != nil {
		back(w, r, "", err.Error())
		return
	}
	_, _ = ad.db.Exec(`UPDATE hosts SET policy=?, allow=? WHERE name=?`, pol, allow, name)
	audit(ad.db, "host_policy", name, pol, "ok", "admin")
	back(w, r, "Updated "+name, "")
}

func (ad *admin) clientRevoke(w http.ResponseWriter, r *http.Request, _ string) {
	id := r.PostForm.Get("id")
	_, _ = ad.db.Exec(`DELETE FROM oauth_tokens WHERE client_id=?`, id)
	_, _ = ad.db.Exec(`DELETE FROM oauth_clients WHERE id=?`, id)
	audit(ad.db, "client_revoke", "", id, "ok", "admin")
	back(w, r, "Client revoked", "")
}

func (ad *admin) tokenNew(w http.ResponseWriter, r *http.Request, _ string) {
	csrf, _, _ := ad.session(r)
	label := strings.TrimSpace(r.PostForm.Get("label"))
	if label == "" || len(label) > 40 || strings.Trim(label, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-") != "" {
		back(w, r, "", "Label: letters, digits, space . _ - (max 40)")
		return
	}
	id := randToken(16)
	tok := "sshmcp_" + randToken(32)
	_, e1 := ad.db.Exec(`INSERT INTO oauth_clients(id,name,redirect_uris,created) VALUES(?,?,?,?)`, id, "API token: "+label, "[]", time.Now().Unix())
	_, e2 := ad.db.Exec(`INSERT INTO oauth_tokens(hash,kind,client_id,expires) VALUES(?,?,?,?)`, hashToken(tok), "access", id, int64(4102444800))
	if e1 != nil || e2 != nil {
		back(w, r, "", "Could not create token")
		return
	}
	audit(ad.db, "token_new", "", label, "ok", "admin")
	d := ad.dashboardData(csrf, "Token created", "")
	d.NewToken = tok
	w.Header().Set("Cache-Control", "no-store")
	ad.render(w, 200, d)
}

// ---- account ----

// verifyCurrent rate-limits and checks the current password for sensitive changes.
func (ad *admin) verifyCurrent(r *http.Request) bool {
	ip := clientIP(r)
	if ad.auth.locked(ip) {
		return false
	}
	ok := bcrypt.CompareHashAndPassword([]byte(getSetting(ad.db, "pw_hash")), []byte(r.PostForm.Get("current"))) == nil
	if !ok {
		ad.auth.recordFail(ip)
		audit(ad.db, "account", "", ip, "current password wrong", "admin")
	}
	return ok
}

func (ad *admin) accPassword(w http.ResponseWriter, r *http.Request, sess string) {
	if !ad.verifyCurrent(r) {
		back(w, r, "", "Current password wrong (or too many attempts)")
		return
	}
	nw := r.PostForm.Get("new")
	switch {
	case len(nw) < 12:
		back(w, r, "", "New password must be at least 12 characters")
		return
	case len(nw) > 72:
		back(w, r, "", "New password too long (max 72 bytes)")
		return
	case nw != r.PostForm.Get("repeat"):
		back(w, r, "", "Passwords differ")
		return
	case nw == r.PostForm.Get("current"):
		back(w, r, "", "New password must differ")
		return
	}
	h, err := bcrypt.GenerateFromPassword([]byte(nw), 12)
	if err != nil {
		back(w, r, "", "Could not hash password")
		return
	}
	_ = setSetting(ad.db, "pw_hash", string(h))
	_ = setSetting(ad.db, "pw_temp", "0")
	_, _ = ad.db.Exec(`DELETE FROM sessions WHERE hash<>?`, sess)
	_, _ = ad.db.Exec(`DELETE FROM oauth_tokens`)
	audit(ad.db, "account", "", "", "password changed; other sessions and AI clients revoked", "admin")
	back(w, r, "Password changed. Other sessions and AI clients were signed out.", "")
}

func (ad *admin) accUsername(w http.ResponseWriter, r *http.Request, _ string) {
	if !ad.verifyCurrent(r) {
		back(w, r, "", "Current password wrong (or too many attempts)")
		return
	}
	u := strings.TrimSpace(r.PostForm.Get("username"))
	if !regexp.MustCompile(`^[A-Za-z0-9._-]{3,32}$`).MatchString(u) {
		back(w, r, "", "Username: 3-32 letters, digits, . _ -")
		return
	}
	_ = setSetting(ad.db, "admin_user", u)
	audit(ad.db, "account", "", u, "username changed", "admin")
	back(w, r, "Username changed", "")
}

func (ad *admin) totpStart(w http.ResponseWriter, r *http.Request, _ string) {
	k, err := totp.Generate(totp.GenerateOpts{Issuer: "sshmcp", AccountName: getSetting(ad.db, "admin_user")})
	if err != nil {
		back(w, r, "", "Could not generate secret")
		return
	}
	_ = setSetting(ad.db, "totp_pending", k.Secret())
	back(w, r, "Scan or enter the secret, then confirm with a code", "")
}

func (ad *admin) totpEnable(w http.ResponseWriter, r *http.Request, _ string) {
	sec := getSetting(ad.db, "totp_pending")
	if sec == "" || !totp.Validate(strings.TrimSpace(r.PostForm.Get("code")), sec) {
		back(w, r, "", "Code did not match; try again")
		return
	}
	_ = setSetting(ad.db, "totp_secret", sec)
	_ = setSetting(ad.db, "totp_pending", "")
	audit(ad.db, "account", "", "", "TOTP enabled", "admin")
	back(w, r, "Authenticator code enabled", "")
}

func (ad *admin) totpDisable(w http.ResponseWriter, r *http.Request, _ string) {
	if !ad.verifyCurrent(r) {
		back(w, r, "", "Current password wrong (or too many attempts)")
		return
	}
	_ = setSetting(ad.db, "totp_secret", "")
	_ = setSetting(ad.db, "totp_pending", "")
	audit(ad.db, "account", "", "", "TOTP disabled", "admin")
	back(w, r, "Authenticator code disabled", "")
}
