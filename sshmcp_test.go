package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
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
	a := newAuthServer(db, "https://mcp.test")
	ad := newAdmin(db, a)
	mux := http.NewServeMux()
	a.routes(mux)
	ad.routes(mux)
	return a, ad, mux
}

func TestRedirectAllowlist(t *testing.T) {
	ok := []string{"https://claude.ai/api/mcp/auth_callback", "https://chatgpt.com/connector_platform_oauth_redirect", "https://claude.com/api/mcp/auth_callback"}
	bad := []string{"http://claude.ai/x", "https://evil.example/cb", "https://claude.ai.evil.com/cb", "https://user@claude.ai/cb", "javascript:alert(1)", "https://localhost/cb"}
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
		f := url.Values{"csrf": {csrf}, "client_id": {reg.ClientID}, "redirect_uri": {redirect}, "state": {"s1"}, "code_challenge": {challenge}, "password": {pw}, "totp": {code}}
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
