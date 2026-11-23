# sshmcp

Self-hosted MCP server that gives Claude and ChatGPT SSH access to your VPSs.
Go, SQLite, Caddy. OAuth 2.1 (PKCE, dynamic client registration) with redirects restricted to claude.ai, claude.com, chatgpt.com and platform.openai.com.

- Admin panel at `/admin` (username + password, optional TOTP): add a server by IP, port, username and password or key; per-host policy (read-only, allowlist, full); audit log; revoke clients.
- Credentials encrypted with AES-256-GCM; master key in a separate 0600 file.
- Host keys are pinned on add (confirm the fingerprint); mismatches are refused.
- MCP tools: `list_hosts`, `host_status`, `ssh_exec`, `sftp_list`, `sftp_read`, `sftp_write`.
- Connector URL: `https://<issuer>/mcp`

Setup: `sshmcp passwd --user NAME` (TOTP optional, enable it in the dashboard), then `sshmcp serve` with `SSHMCP_ISSUER` set. See `deploy/`.
