package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pkg/sftp"
)

type ctxKey string

const clientKey ctxKey = "client"

func clientFrom(ctx context.Context) string {
	s, _ := ctx.Value(clientKey).(string)
	return s
}

func boolp(b bool) *bool { return &b }

type hostInfo struct {
	Name   string `json:"name"`
	Addr   string `json:"addr"`
	User   string `json:"user"`
	Policy string `json:"policy"`
	Note   string `json:"note,omitempty"`
}

type listIn struct{}
type listOut struct {
	Hosts []hostInfo `json:"hosts"`
}

type execIn struct {
	Host    string `json:"host" jsonschema:"host name from list_hosts"`
	Command string `json:"command" jsonschema:"shell command to run"`
	Timeout int    `json:"timeout_s,omitempty" jsonschema:"timeout in seconds (default 60, max 300)"`
}

type statusIn struct {
	Host string `json:"host" jsonschema:"host name from list_hosts"`
}
type statusOut struct {
	Output string `json:"output"`
}

type lsIn struct {
	Host string `json:"host" jsonschema:"host name from list_hosts"`
	Path string `json:"path" jsonschema:"absolute directory path"`
}
type lsEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime string `json:"mtime"`
	IsDir   bool   `json:"is_dir"`
}
type lsOut struct {
	Entries []lsEntry `json:"entries"`
}

type readIn struct {
	Host string `json:"host" jsonschema:"host name from list_hosts"`
	Path string `json:"path" jsonschema:"absolute file path (max 1 MiB)"`
}
type readOut struct {
	Content   string `json:"content"`
	Encoding  string `json:"encoding"`
	Truncated bool   `json:"truncated,omitempty"`
}

type writeIn struct {
	Host     string `json:"host" jsonschema:"host name from list_hosts"`
	Path     string `json:"path" jsonschema:"absolute file path"`
	Content  string `json:"content" jsonschema:"file content (max 1 MiB)"`
	Encoding string `json:"encoding,omitempty" jsonschema:"utf8 (default) or base64"`
	Mode     uint32 `json:"mode,omitempty" jsonschema:"octal permission bits as decimal, e.g. 420 for 0644 (default 420)"`
}
type writeOut struct {
	Bytes int `json:"bytes"`
}

func registerTools(s *mcp.Server, db *sql.DB) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_hosts",
		Description: "List the SSH hosts this server can reach, with their policy (readonly, allowlist or full).",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ listIn) (*mcp.CallToolResult, listOut, error) {
		hs, err := listHosts(db)
		if err != nil {
			return nil, listOut{}, err
		}
		out := listOut{Hosts: []hostInfo{}}
		for _, h := range hs {
			out.Hosts = append(out.Hosts, hostInfo{h.Name, h.Addr, h.User, h.Policy, h.Note})
		}
		sort.Slice(out.Hosts, func(i, j int) bool { return out.Hosts[i].Name < out.Hosts[j].Name })
		audit(db, "list_hosts", "", "", "ok", clientFrom(ctx))
		return nil, out, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "host_status",
		Description: "Fixed read-only health snapshot: uptime, load, memory, disk, failed units.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in statusIn) (*mcp.CallToolResult, statusOut, error) {
		h, err := loadHost(db, in.Host)
		if err != nil {
			return nil, statusOut{}, err
		}
		const cmd = `uptime; echo; free -h | head -2; echo; df -h / | tail -1; echo; systemctl --failed --no-legend 2>/dev/null | head -10`
		res, err := h.exec(ctx, cmd, 20*time.Second)
		if err != nil {
			audit(db, "host_status", h.Name, "", "error: "+err.Error(), clientFrom(ctx))
			return nil, statusOut{}, err
		}
		audit(db, "host_status", h.Name, "", "ok", clientFrom(ctx))
		return nil, statusOut{Output: res.Stdout + res.Stderr}, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "ssh_exec",
		Description: "Run a shell command on a host. Subject to the host's policy. Output is capped at 256 KiB.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolp(true), OpenWorldHint: boolp(false)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in execIn) (*mcp.CallToolResult, ExecResult, error) {
		h, err := loadHost(db, in.Host)
		if err != nil {
			return nil, ExecResult{}, err
		}
		if err := h.allowExec(in.Command); err != nil {
			audit(db, "ssh_exec", h.Name, in.Command, "denied: "+err.Error(), clientFrom(ctx))
			return nil, ExecResult{}, err
		}
		res, err := h.exec(ctx, in.Command, time.Duration(in.Timeout)*time.Second)
		if err != nil {
			audit(db, "ssh_exec", h.Name, in.Command, "error: "+err.Error(), clientFrom(ctx))
			return nil, ExecResult{}, err
		}
		audit(db, "ssh_exec", h.Name, in.Command, fmt.Sprintf("exit=%d timeout=%v", res.ExitCode, res.TimedOut), clientFrom(ctx))
		return nil, *res, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "sftp_list",
		Description: "List a remote directory.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in lsIn) (*mcp.CallToolResult, lsOut, error) {
		h, err := loadHost(db, in.Host)
		if err != nil {
			return nil, lsOut{}, err
		}
		p, err := cleanRemotePath(in.Path)
		if err != nil {
			return nil, lsOut{}, err
		}
		out := lsOut{Entries: []lsEntry{}}
		err = h.withSFTP(ctx, func(sc *sftp.Client) error {
			fis, err := sc.ReadDir(p)
			if err != nil {
				return err
			}
			for i, fi := range fis {
				if i >= 2000 {
					break
				}
				out.Entries = append(out.Entries, lsEntry{fi.Name(), fi.Size(), fi.Mode().String(), fi.ModTime().UTC().Format(time.RFC3339), fi.IsDir()})
			}
			return nil
		})
		res := "ok"
		if err != nil {
			res = "error: " + err.Error()
		}
		audit(db, "sftp_list", h.Name, p, res, clientFrom(ctx))
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "sftp_read",
		Description: "Read a remote file (max 1 MiB). Private keys, shadow and .ssh paths are blocked. Binary content is returned base64-encoded.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in readIn) (*mcp.CallToolResult, readOut, error) {
		h, err := loadHost(db, in.Host)
		if err != nil {
			return nil, readOut{}, err
		}
		p, err := cleanRemotePath(in.Path)
		if err != nil {
			return nil, readOut{}, err
		}
		if err := allowRead(p); err != nil {
			audit(db, "sftp_read", h.Name, p, "denied: "+err.Error(), clientFrom(ctx))
			return nil, readOut{}, err
		}
		var out readOut
		err = h.withSFTP(ctx, func(sc *sftp.Client) error {
			// Resolve symlinks so a link cannot bypass the path blocklist.
			real, err := sc.RealPath(p)
			if err != nil {
				return err
			}
			if err := allowRead(real); err != nil {
				return err
			}
			f, err := sc.Open(real)
			if err != nil {
				return err
			}
			defer f.Close()
			b, trunc, err := readAllCapped(f, maxFileRead)
			if err != nil {
				return err
			}
			out.Truncated = trunc
			if utf8.Valid(b) {
				out.Content, out.Encoding = string(b), "utf8"
			} else {
				out.Content, out.Encoding = base64.StdEncoding.EncodeToString(b), "base64"
			}
			return nil
		})
		res := "ok"
		if err != nil {
			res = "error: " + err.Error()
		}
		audit(db, "sftp_read", h.Name, p, res, clientFrom(ctx))
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "sftp_write",
		Description: "Write a remote file (max 1 MiB). Only on hosts with policy 'full'. Overwrites existing files.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolp(true), OpenWorldHint: boolp(false)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in writeIn) (*mcp.CallToolResult, writeOut, error) {
		h, err := loadHost(db, in.Host)
		if err != nil {
			return nil, writeOut{}, err
		}
		p, err := cleanRemotePath(in.Path)
		if err != nil {
			return nil, writeOut{}, err
		}
		if h.Policy != "full" {
			audit(db, "sftp_write", h.Name, p, "denied: policy "+h.Policy, clientFrom(ctx))
			return nil, writeOut{}, fmt.Errorf("writes need policy 'full'; host is %q", h.Policy)
		}
		var data []byte
		switch strings.ToLower(in.Encoding) {
		case "", "utf8":
			data = []byte(in.Content)
		case "base64":
			data, err = base64.StdEncoding.DecodeString(in.Content)
			if err != nil {
				return nil, writeOut{}, fmt.Errorf("bad base64: %w", err)
			}
		default:
			return nil, writeOut{}, fmt.Errorf("encoding must be utf8 or base64")
		}
		if len(data) > maxFileWrit {
			return nil, writeOut{}, fmt.Errorf("content exceeds 1 MiB")
		}
		mode := os.FileMode(in.Mode)
		if in.Mode == 0 {
			mode = 0o644
		}
		mode &= 0o777
		err = h.withSFTP(ctx, func(sc *sftp.Client) error {
			f, err := sc.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
			if err != nil {
				return err
			}
			if _, err := f.Write(data); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			return sc.Chmod(p, mode)
		})
		res := "ok"
		if err != nil {
			res = "error: " + err.Error()
		}
		audit(db, "sftp_write", h.Name, fmt.Sprintf("%s (%d bytes)", p, len(data)), res, clientFrom(ctx))
		return nil, writeOut{Bytes: len(data)}, err
	})
}
