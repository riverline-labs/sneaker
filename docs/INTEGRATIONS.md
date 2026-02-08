# External Integrations

**Analysis Date:** 2026-02-07

## APIs & External Services

**None:**
- No external API dependencies
- No third-party SaaS integrations
- Fully self-contained service

## Data Storage

**Databases:**
- SQLite (file-based)
  - Connection: Configured via `--db` flag (default: `sneaker.db`)
  - Client: `modernc.org/sqlite` v1.44.3 (pure Go, no CGo)
  - Mode: WAL (Write-Ahead Logging) for concurrency
  - Connection pools: Dual (1 writer at `internal/store/sqlite.go:45`, 10 readers at line 53)
  - Migrations: Embedded in binary via `go:embed` at `internal/store/sqlite.go:16`

**File Storage:**
- Local filesystem only
  - Database file: `sneaker.db` (or custom path)
  - Config file: `~/.config/sneaker/config.json` (CLI only)

**Caching:**
- None (in-memory session tracking only)

## Authentication & Identity

**Auth Provider:**
- Custom (built-in)
  - Implementation: Argon2id password hashing at `internal/auth/auth.go`
  - Parameters: 64 MB memory, 3 iterations, parallelism=2 (RFC 9106 compliant)
  - Session tokens: Random 32-byte tokens stored in database
  - Session expiry: 30 days default (cleaned every 5 minutes at `internal/server/server.go:107-127`)
  - Public key infrastructure: age X25519 keys for identity-based encryption

## Monitoring & Observability

**Error Tracking:**
- None

**Logs:**
- Structured logging via `log/slog` (Go stdlib)
- Outputs: stderr (server), stdout (CLI responses)
- Request logging middleware at `internal/server/middleware.go`

## CI/CD & Deployment

**Hosting:**
- Self-hosted (no platform detected)
- Designed for deployment behind TLS-terminating reverse proxy

**CI Pipeline:**
- None detected (no `.github/workflows/`, `.gitlab-ci.yml`, etc.)

## Environment Configuration

**Required env vars:**
- None (all configuration via flags or config file)

**Secrets location:**
- User passwords: Hashed in SQLite `users` table
- Session tokens: Stored in SQLite `sessions` table
- Age encryption keys: Stored in SQLite `identities` table
- CLI config: `~/.config/sneaker/config.json` (contains auth token)

## Webhooks & Callbacks

**Incoming:**
- None

**Outgoing:**
- None

## Security Features

**CSRF Protection:**
- Fetch Metadata headers via `http.NewCrossOriginProtection()` at `internal/server/server.go:42-43`

**Encryption:**
- End-to-end via `filippo.io/age` library
- Link mode: Ephemeral X25519 keypair at `cmd/send.go:70-90`
- Identity mode: Recipient's registered X25519 public key at `cmd/send.go:168-186`
- Passphrase protection: Optional scrypt layer at `cmd/send.go:92-118`

**TLS:**
- Not implemented in application (relies on reverse proxy)
- Warning displayed at startup (`internal/server/server.go:177-188`)

---

*Integration audit: 2026-02-07*
