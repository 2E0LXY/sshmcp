package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	maxOutput   = 256 * 1024
	maxFileRead = 1024 * 1024
	maxFileWrit = 1024 * 1024
	dialTimeout = 10 * time.Second
	defaultExec = 60 * time.Second
	maxExec     = 300 * time.Second
)

type Host struct {
	Name, Addr, User, Auth, Secret, HostKey, Policy, Allow, Note string
	Port                                                         int
}

func loadHost(db *sql.DB, name string) (*Host, error) {
	h := &Host{}
	err := db.QueryRow(`SELECT name,addr,port,user,auth,secret,host_key,policy,allow,note FROM hosts WHERE name=?`, name).
		Scan(&h.Name, &h.Addr, &h.Port, &h.User, &h.Auth, &h.Secret, &h.HostKey, &h.Policy, &h.Allow, &h.Note)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("unknown host %q (use list_hosts)", name)
	}
	return h, err
}

func listHosts(db *sql.DB) ([]Host, error) {
	rows, err := db.Query(`SELECT name,addr,port,user,auth,secret,host_key,policy,allow,note FROM hosts ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		var h Host
		if err := rows.Scan(&h.Name, &h.Addr, &h.Port, &h.User, &h.Auth, &h.Secret, &h.HostKey, &h.Policy, &h.Allow, &h.Note); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// dial connects using the pinned host key only. A mismatch is a hard failure.
func (h *Host) dial(ctx context.Context) (*ssh.Client, error) {
	secret, err := vault.Open(h.Secret)
	if err != nil {
		return nil, err
	}
	var auth []ssh.AuthMethod
	if h.Auth == "key" {
		signer, err := ssh.ParsePrivateKey([]byte(secret))
		if err != nil {
			return nil, fmt.Errorf("parse key: %w", err)
		}
		auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		auth = []ssh.AuthMethod{
			ssh.Password(secret),
			ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				as := make([]string, len(qs))
				for i := range as {
					as[i] = secret
				}
				return as, nil
			}),
		}
	}
	pinned, _, _, _, err := ssh.ParseAuthorizedKey([]byte(h.HostKey))
	if err != nil {
		return nil, fmt.Errorf("pinned host key invalid: %w", err)
	}
	cfg := &ssh.ClientConfig{
		User:              h.User,
		Auth:              auth,
		HostKeyCallback:   ssh.FixedHostKey(pinned),
		HostKeyAlgorithms: hostKeyAlgs(pinned),
		Timeout:           dialTimeout,
	}
	addr := net.JoinHostPort(h.Addr, fmt.Sprint(h.Port))
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

type capBuf struct {
	buf       bytes.Buffer
	truncated bool
}

func (c *capBuf) Write(p []byte) (int, error) {
	if c.buf.Len() >= maxOutput {
		c.truncated = true
		return len(p), nil
	}
	room := maxOutput - c.buf.Len()
	if len(p) > room {
		c.buf.Write(p[:room])
		c.truncated = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *capBuf) String() string {
	s := strings.ToValidUTF8(c.buf.String(), "�")
	if c.truncated {
		s += "\n[output truncated at 256 KiB]"
	}
	return s
}

type ExecResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	TimedOut bool   `json:"timed_out,omitempty"`
}

func (h *Host) exec(ctx context.Context, cmd string, timeout time.Duration) (*ExecResult, error) {
	if timeout <= 0 {
		timeout = defaultExec
	}
	if timeout > maxExec {
		timeout = maxExec
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, err := h.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	var so, se capBuf
	sess.Stdout, sess.Stderr = &so, &se
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	res := &ExecResult{}
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		client.Close()
		res.TimedOut = true
		res.ExitCode = -1
		res.Stdout, res.Stderr = so.String(), se.String()
		return res, nil
	}
	var ee *ssh.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitStatus()
	default:
		return nil, err
	}
	res.Stdout, res.Stderr = so.String(), se.String()
	return res, nil
}

func (h *Host) withSFTP(ctx context.Context, fn func(*sftp.Client) error) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	client, err := h.dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	sc, err := sftp.NewClient(client)
	if err != nil {
		return err
	}
	defer sc.Close()
	return fn(sc)
}

// ---- policy ----

var shellMeta = regexp.MustCompile("[;&|`$<>\\n\\r(){}\\\\]")

// allowExec decides whether a command may run under the host policy.
func (h *Host) allowExec(cmd string) error {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return errors.New("empty command")
	}
	switch h.Policy {
	case "full":
		return nil
	case "readonly":
		return errors.New("host is read-only: ssh_exec disabled (sftp_list/sftp_read/host_status still work)")
	case "allowlist":
		if shellMeta.MatchString(cmd) {
			return errors.New("allowlist hosts reject shell metacharacters ; & | ` $ < > ( ) { } \\ and newlines")
		}
		for _, pat := range strings.Split(h.Allow, "\n") {
			pat = strings.TrimSpace(pat)
			if pat == "" {
				continue
			}
			re, err := regexp.Compile("^(?:" + pat + ")$")
			if err != nil {
				continue
			}
			if re.MatchString(cmd) {
				return nil
			}
		}
		return errors.New("command not in allowlist for this host")
	}
	return errors.New("invalid policy")
}

var sensitivePaths = []string{"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/proc/kcore"}

func cleanRemotePath(p string) (string, error) {
	if p == "" || !strings.HasPrefix(p, "/") {
		return "", errors.New("path must be absolute")
	}
	if strings.ContainsRune(p, 0) {
		return "", errors.New("invalid path")
	}
	return path.Clean(p), nil
}

// allowRead blocks obviously sensitive files regardless of policy.
func allowRead(p string) error {
	for _, s := range sensitivePaths {
		if p == s || strings.HasPrefix(p, s+"/") {
			return fmt.Errorf("reading %s is blocked", s)
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".ssh" || seg == ".gnupg" {
			return errors.New("reading .ssh / .gnupg is blocked")
		}
	}
	base := path.Base(p)
	if strings.HasPrefix(base, "id_") || strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") {
		return errors.New("reading private key files is blocked")
	}
	return nil
}

func readAllCapped(r io.Reader, n int64) ([]byte, bool, error) {
	b, err := io.ReadAll(io.LimitReader(r, n+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > n {
		return b[:n], true, nil
	}
	return b, false, nil
}

// hostKeyAlgs maps a pinned key to the signature algorithms servers accept.
// RSA host keys must be negotiated as rsa-sha2-*; plain ssh-rsa (SHA-1) is refused.
func hostKeyAlgs(k ssh.PublicKey) []string {
	if k.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{k.Type()}
}

// scanAlgs is the preference order used when first fetching a host key.
var scanAlgs = []string{
	ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}
