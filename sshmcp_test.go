package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

func testEnv(t *testing.T) (*authServer, *admin, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	vault, err = loadVault(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	h, _ := bcrypt.GenerateFromPassword([]byte("correct horse battery"), bcrypt.MinCost)
	_ = setSetting(db, "pw_hash", string(h))
	_ = setSetting(db, "totp_secret", "JBSWY3DPEHPK3PXP")
	_ = setSetting(db, "admin_user", "admin")
	a := newAuthServer(db, "https://mcp.test")
	ad := newAdmin(db, a)
	mux := http.NewServeMux()
	a.routes(mux)
	ad.routes(mux)
	return a, ad, mux
}

func TestRedirectAllowlist(t *testing.T) {
	ok := []string{"https://claude.ai/api/mcp/auth_callback", "https://chatgpt.com/connector_platform_oauth_redirect", "https://claude.com/api/mcp/auth_callback", "http://127.0.0.1:38213/callback", "http://localhost:1455/auth/callback", "http://[::1]:5000/cb"}
	bad := []string{"http://claude.ai/x", "https://evil.example/cb", "https://claude.ai.evil.com/cb", "https://user@claude.ai/cb", "javascript:alert(1)", "https://localhost/cb", "http://evil.example/cb", "http://127.0.0.1.evil.com/cb", "http://claude.ai/x"}
	for _, u := range ok {
		if !redirectAllowed(u) {
			t.Errorf("should allow %s", u)
		}
	}
	for _, u := range bad {
		if redirectAllowed(u) {
			t.Errorf("should reject %s", u)
		}
	}
}

func TestOAuthFlow(t *testing.T) {
	a, _, mux := testEnv(t)
	do := func(req *http.Request) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	// DCR: bad redirect rejected, good accepted
	bad := httptest.NewRequest("POST", "/register", strings.NewReader(`{"client_name":"x","redirect_uris":["https://evil.example/cb"]}`))
	if rr := do(bad); rr.Code != 400 {
		t.Fatalf("evil redirect accepted: %d", rr.Code)
	}
	redirect := "https://claude.ai/api/mcp/auth_callback"
	rr := do(httptest.NewRequest("POST", "/register", strings.NewReader(`{"client_name":"Claude","redirect_uris":["`+redirect+`"]}`)))
	if rr.Code != 201 {
		t.Fatalf("register: %d %s", rr.Code, rr.Body)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &reg)

	verifier := randToken(40)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	q := url.Values{"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {redirect}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"s1"}}

	get := httptest.NewRequest("GET", "/authorize?"+q.Encode(), nil)
	gr := do(get)
	if gr.Code != 200 {
		t.Fatalf("authorize GET: %d %s", gr.Code, gr.Body)
	}
	var csrf string
	for _, c := range gr.Result().Cookies() {
		if c.Name == "csrf" {
			csrf = c.Value
		}
	}
	post := func(pw, code string) *httptest.ResponseRecorder {
		f := url.Values{"csrf": {csrf}, "client_id": {reg.ClientID}, "redirect_uri": {redirect}, "state": {"s1"}, "code_challenge": {challenge}, "username": {"admin"}, "password": {pw}, "totp": {code}}
		req := httptest.NewRequest("POST", "/authorize", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "csrf", Value: csrf})
		return do(req)
	}
	if r := post("wrong", "000000"); r.Code != 401 {
		t.Fatalf("wrong creds: %d", r.Code)
	}
	good, _ := totp.GenerateCode("JBSWY3DPEHPK3PXP", time.Now())
	r := post("correct horse battery", good)
	if r.Code != 302 {
		t.Fatalf("login: %d %s", r.Code, r.Body)
	}
	loc, _ := url.Parse(r.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" || loc.Query().Get("state") != "s1" || loc.Host != "claude.ai" {
		t.Fatalf("bad redirect %s", loc)
	}
	tok := func(f url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/token", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return do(req)
	}
	// wrong verifier burns the code
	if r := tok(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {"nope"}, "client_id": {reg.ClientID}, "redirect_uri": {redirect}}); r.Code != 400 {
		t.Fatalf("bad verifier accepted: %d", r.Code)
	}
	if r := tok(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "client_id": {reg.ClientID}, "redirect_uri": {redirect}}); r.Code != 400 {
		t.Fatalf("code reuse accepted: %d", r.Code)
	}
	// fresh code, correct verifier
	good2, _ := totp.GenerateCode("JBSWY3DPEHPK3PXP", time.Now())
	r = post("correct horse battery", good2)
	loc, _ = url.Parse(r.Header().Get("Location"))
	tr := tok(url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "code_verifier": {verifier}, "client_id": {reg.ClientID}, "redirect_uri": {redirect}})
	if tr.Code != 200 {
		t.Fatalf("token: %d %s", tr.Code, tr.Body)
	}
	var tj map[string]any
	_ = json.Unmarshal(tr.Body.Bytes(), &tj)
	rt := tj["refresh_token"].(string)
	rr2 := tok(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
	if rr2.Code != 200 {
		t.Fatalf("refresh: %d", rr2.Code)
	}
	if r := tok(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}); r.Code != 400 {
		t.Fatalf("old refresh token reusable: %d", r.Code)
	}
	_ = a
}

func TestLoginLockout(t *testing.T) {
	a, _, _ := testEnv(t)
	for i := 0; i < 5; i++ {
		a.recordFail("1.2.3.4")
	}
	if !a.locked("1.2.3.4") || a.locked("5.6.7.8") {
		t.Fatal("lockout wrong")
	}
}

func TestPolicy(t *testing.T) {
	ro := &Host{Policy: "readonly"}
	if ro.allowExec("ls") == nil {
		t.Error("readonly allowed exec")
	}
	al := &Host{Policy: "allowlist", Allow: "uptime\ndf -h\nsystemctl status [a-z.-]+"}
	for _, c := range []string{"uptime", "df -h", "systemctl status caddy"} {
		if err := al.allowExec(c); err != nil {
			t.Errorf("%q denied: %v", c, err)
		}
	}
	for _, c := range []string{"uptime; rm -rf /", "uptime && id", "uptime | sh", "df -h $(id)", "cat /etc/passwd", "uptime\nid", "systemctl status `id`"} {
		if al.allowExec(c) == nil {
			t.Errorf("%q allowed", c)
		}
	}
	if (&Host{Policy: "full"}).allowExec("anything") != nil {
		t.Error("full denied")
	}
	for _, p := range []string{"/etc/shadow", "/root/.ssh/id_ed25519", "/home/a/.ssh/authorized_keys", "/srv/x/server.key", "/srv/cert.pem"} {
		if allowRead(p) == nil {
			t.Errorf("read %s allowed", p)
		}
	}
	if allowRead("/etc/caddy/Caddyfile") != nil {
		t.Error("caddyfile blocked")
	}
	if _, err := cleanRemotePath("relative/path"); err == nil {
		t.Error("relative path accepted")
	}
}

func TestVault(t *testing.T) {
	testEnv(t)
	enc, _ := vault.Seal("s3cret")
	if enc == "s3cret" || strings.Contains(enc, "s3cret") {
		t.Fatal("not encrypted")
	}
	if p, err := vault.Open(enc); err != nil || p != "s3cret" {
		t.Fatalf("roundtrip: %v %q", err, p)
	}
}

// fakeSSH starts an in-process SSH server that accepts one password and
// answers every exec request with "ran: <cmd>".
func fakeSSH(t *testing.T, password string) (addr string, port int, hostKey ssh.PublicKey) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if string(pw) == password {
			return nil, nil
		}
		return nil, errBadPW
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, _ := nc.Accept()
					go func() {
						for r := range creqs {
							if r.Type == "exec" {
								cmd := string(r.Payload[4:])
								_ = r.Reply(true, nil)
								_, _ = ch.Write([]byte("ran: " + cmd))
								_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
								ch.Close()
								return
							}
							_ = r.Reply(false, nil)
						}
					}()
				}
			}()
		}
	}()
	tcp := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", tcp.Port, signer.PublicKey()
}

type strErr string

func (e strErr) Error() string { return string(e) }

const errBadPW = strErr("bad password")

func TestSSHExecAndPinning(t *testing.T) {
	testEnv(t)
	addr, port, hk := fakeSSH(t, "pw123")
	enc, _ := vault.Seal("pw123")
	h := &Host{Name: "t", Addr: addr, Port: port, User: "u", Auth: "password", Secret: enc, HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hk))), Policy: "full"}
	res, err := h.exec(context.Background(), "echo hi", 10*time.Second)
	if err != nil || res.Stdout != "ran: echo hi" || res.ExitCode != 0 {
		t.Fatalf("exec: %v %+v", err, res)
	}
	// scan captures the key without sending credentials
	got, err := scanHostKey(context.Background(), addr, port)
	if err != nil || string(got.Marshal()) != string(hk.Marshal()) {
		t.Fatalf("scan: %v", err)
	}
	// wrong password
	bad, _ := vault.Seal("wrong")
	h2 := *h
	h2.Secret = bad
	if _, err := h2.exec(context.Background(), "id", 10*time.Second); err == nil {
		t.Fatal("wrong password accepted")
	}
	// pinned key mismatch must be refused
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	os, _ := ssh.NewSignerFromKey(other)
	h3 := *h
	h3.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(os.PublicKey())))
	if _, err := h3.exec(context.Background(), "id", 10*time.Second); err == nil {
		t.Fatal("host key mismatch accepted")
	}
}

func TestCredsOK(t *testing.T) {
	a, _, _ := testEnv(t)
	code, _ := totp.GenerateCode("JBSWY3DPEHPK3PXP", time.Now())
	if !a.credsOK("admin", "correct horse battery", code) {
		t.Fatal("valid creds rejected")
	}
	if a.credsOK("other", "correct horse battery", code) || a.credsOK("admin", "bad", code) || a.credsOK("admin", "correct horse battery", "000000") {
		t.Fatal("bad creds accepted")
	}
	_ = setSetting(a.db, "totp_secret", "") // TOTP optional
	if !a.credsOK("admin", "correct horse battery", "") {
		t.Fatal("no-TOTP login rejected")
	}
	if a.credsOK("admin", "wrong", "") || a.credsOK("nobody", "correct horse battery", "") {
		t.Fatal("no-TOTP bad creds accepted")
	}
}

func TestGlobalThrottle(t *testing.T) {
	a, _, _ := testEnv(t)
	for i := 0; i < 30; i++ {
		a.recordFail(fmt.Sprintf("10.0.0.%d", i))
	}
	if !a.locked("203.0.113.9") {
		t.Fatal("global throttle did not engage")
	}
}

func TestAdminAccountFlow(t *testing.T) {
	a, _, mux := testEnv(t)
	_ = setSetting(a.db, "totp_secret", "")
	_ = setSetting(a.db, "pw_temp", "1")
	do := func(req *http.Request, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	form := func(path string, v url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return do(req, cookies...)
	}
	if r := form("/admin/login", url.Values{"username": {"admin"}, "password": {"nope"}}); r.Code != 401 {
		t.Fatalf("bad login: %d", r.Code)
	}
	r := form("/admin/login", url.Values{"username": {"admin"}, "password": {"correct horse battery"}})
	if r.Code != 303 {
		t.Fatalf("login: %d %s", r.Code, r.Body)
	}
	var sess *http.Cookie
	for _, c := range r.Result().Cookies() {
		if c.Name == "sshmcp_sess" {
			sess = c
		}
	}
	d := do(httptest.NewRequest("GET", "/admin", nil), sess)
	if d.Code != 200 || !strings.Contains(d.Body.String(), "Temporary password in use") {
		t.Fatalf("dashboard: %d temp banner missing", d.Code)
	}
	csrf, _, _ := (&admin{db: a.db}).session(func() *http.Request { q := httptest.NewRequest("GET", "/", nil); q.AddCookie(sess); return q }())
	// API token: created once, accepted by bearer middleware, revocable
	tr := form("/admin/tokens/new", url.Values{"csrf": {csrf}, "label": {"codex"}}, sess)
	m := regexp.MustCompile(`sshmcp_[A-Za-z0-9_-]+`).FindString(tr.Body.String())
	if tr.Code != 200 || m == "" {
		t.Fatalf("token create: %d", tr.Code)
	}
	if bad := form("/admin/tokens/new", url.Values{"csrf": {csrf}, "label": {"a<b"}}, sess); bad.Code != 303 {
		t.Fatalf("bad label accepted: %d", bad.Code)
	}
	bh := bearer(a.db, "https://x.example", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	call := func(tok string) int {
		q := httptest.NewRequest("POST", "/mcp", nil)
		q.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		bh.ServeHTTP(rr, q)
		return rr.Code
	}
	if call(m) != 204 || call(m+"x") != 401 {
		t.Fatal("api token not honoured correctly")
	}
	sp := secretPath(a.db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" || r.Context().Value(clientKey) == nil {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(204)
	}))
	surl := func(tok string) int {
		rr := httptest.NewRecorder()
		sp.ServeHTTP(rr, httptest.NewRequest("POST", "/mcp/"+tok, nil))
		return rr.Code
	}
	if surl(m) != 204 || surl(m+"x") != 404 || surl("") != 404 || surl("a/b") != 404 {
		t.Fatal("secret path not honoured correctly")
	}
	var cid string
	_ = a.db.QueryRow(`SELECT id FROM oauth_clients WHERE name='API token: codex'`).Scan(&cid)
	form("/admin/clients/revoke", url.Values{"csrf": {csrf}, "id": {cid}}, sess)
	if call(m) != 401 || surl(m) != 404 {
		t.Fatal("revoked token still valid")
	}
	// short password rejected, wrong current rejected, good change accepted
	loc := func(rr *httptest.ResponseRecorder) string { return rr.Header().Get("Location") }
	if l := loc(form("/admin/account/password", url.Values{"csrf": {csrf}, "current": {"correct horse battery"}, "new": {"short"}, "repeat": {"short"}}, sess)); !strings.Contains(l, "e=") {
		t.Fatalf("short pw accepted: %s", l)
	}
	if l := loc(form("/admin/account/password", url.Values{"csrf": {csrf}, "current": {"wrong"}, "new": {"a much longer password"}, "repeat": {"a much longer password"}}, sess)); !strings.Contains(l, "e=") {
		t.Fatalf("wrong current accepted: %s", l)
	}
	if l := loc(form("/admin/account/password", url.Values{"csrf": {csrf}, "current": {"correct horse battery"}, "new": {"a much longer password"}, "repeat": {"a much longer password"}}, sess)); !strings.Contains(l, "m=") {
		t.Fatalf("change failed: %s", l)
	}
	if getSetting(a.db, "pw_temp") != "0" || !a.credsOK("admin", "a much longer password", "") || a.credsOK("admin", "correct horse battery", "") {
		t.Fatal("password not changed correctly")
	}
	// CSRF required
	if r := form("/admin/account/username", url.Values{"csrf": {"bad"}, "username": {"x1y2z3"}, "current": {"a much longer password"}}, sess); r.Code != 403 {
		t.Fatalf("csrf not enforced: %d", r.Code)
	}
	// TOTP enable flow
	form("/admin/account/totp/start", url.Values{"csrf": {csrf}}, sess)
	sec := getSetting(a.db, "totp_pending")
	code, _ := totp.GenerateCode(sec, time.Now())
	form("/admin/account/totp/enable", url.Values{"csrf": {csrf}, "code": {code}}, sess)
	if getSetting(a.db, "totp_secret") != sec {
		t.Fatal("totp not enabled")
	}
	if a.credsOK("admin", "a much longer password", "") {
		t.Fatal("login without code accepted after enabling TOTP")
	}
}

func TestHostKeyAlgs(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sg, _ := ssh.NewSignerFromKey(priv)
	if a := hostKeyAlgs(sg.PublicKey()); len(a) != 1 || a[0] != ssh.KeyAlgoED25519 {
		t.Fatalf("ed25519: %v", a)
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rs, _ := ssh.NewSignerFromKey(rk)
	a := hostKeyAlgs(rs.PublicKey())
	if len(a) != 2 || a[0] != ssh.KeyAlgoRSASHA512 || a[1] != ssh.KeyAlgoRSASHA256 {
		t.Fatalf("rsa: %v", a)
	}
}

func TestMCPHostHeader(t *testing.T) {
	a, _, _ := testEnv(t)
	srv := newMCPHandler(a.db, "mcp.test")
	tok := "tok-test"
	_, _ = a.db.Exec(`INSERT INTO oauth_tokens VALUES(?,?,?,?)`, hashToken(tok), "access", "c", time.Now().Add(time.Hour).Unix())
	h := bearer(a.db, "https://mcp.test", srv)
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	do := func(host string) int {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
		r.Host = host
		r.Header.Set("Authorization", "Bearer "+tok)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		return rr.Code
	}
	if c := do("mcp.test"); c != 200 {
		t.Fatalf("public host rejected: %d", c)
	}
	if c := do("evil.example"); c != 403 {
		t.Fatalf("foreign host accepted: %d", c)
	}
}
