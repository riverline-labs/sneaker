# Technology Stack

**Analysis Date:** 2026-02-07

## Languages

**Primary:**
- Go 1.25.7 - Backend server, CLI tool, all business logic

**Secondary:**
- JavaScript (ES6+) - Frontend web UI (`web/static/js/`)
- HTML5 - Web templates (`web/*.html`)
- CSS3 - Styling (`web/static/css/style.css`)
- SQL - Database migrations (`internal/store/migrations/*.sql`)

## Runtime

**Environment:**
- Go 1.25.7

**Package Manager:**
- Go modules (go.mod)
- Lockfile: `go.sum` present

## Frameworks

**Core:**
- `net/http` (stdlib) - HTTP server and client
- `github.com/spf13/cobra` v1.10.2 - CLI command structure

**Testing:**
- `github.com/stretchr/testify` v1.11.1 - Test assertions and mocks
- Go testing (stdlib) - Test runner

**Build/Dev:**
- `go:embed` (stdlib) - Embeds web assets into binary at `web.go`
- `github.com/pressly/goose/v3` v3.26.0 - Database migrations

## Key Dependencies

**Critical:**
- `filippo.io/age` v1.3.1 - End-to-end encryption (X25519, scrypt)
- `modernc.org/sqlite` v1.44.3 - Pure-Go SQLite driver (no CGo)
- `golang.org/x/crypto` v0.47.0 - Argon2id password hashing, scrypt, terminal I/O

**Infrastructure:**
- `database/sql` (stdlib) - Database abstraction
- `context` (stdlib) - Cancellation and timeouts
- `log/slog` (stdlib) - Structured logging
- `embed` (stdlib) - Embedded filesystem for migrations and web assets

## Configuration

**Environment:**
- No environment variables required for development
- Configuration stored in `~/.config/sneaker/config.json` for CLI
- Database path configurable via `--db` flag (default: `sneaker.db`)

**Build:**
- `go.mod` - Go module definition
- `web.go` - Embeds `web/` directory into binary
- `internal/store/sqlite.go` - Embeds `migrations/*.sql` at line 16

## Platform Requirements

**Development:**
- Go 1.25.7 or later
- No CGo required (pure Go SQLite driver)
- No external databases or services needed

**Production:**
- Single static binary (includes embedded web assets)
- SQLite database file with 0600 permissions
- Reverse proxy recommended for TLS termination (nginx, caddy)
- Warning issued at startup if TLS not detected (`internal/server/server.go:177-188`)

---

*Stack analysis: 2026-02-07*
