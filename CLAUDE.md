# Sneaker - Claude Code Context

## What is this?

Sneaker is a self-hosted, one-time secret exchange tool. Secrets are end-to-end encrypted using AGE (X25519) and self-destruct after reading. It ships as a single Go binary with an embedded web frontend and SQLite database.

## Codebase Documentation

Detailed codebase analysis is in `.planning/codebase/`:

- `STACK.md` - Languages, runtime, frameworks, dependencies
- `ARCHITECTURE.md` - System design, layers, data flow, entry points
- `STRUCTURE.md` - Directory layout, naming conventions, where to add code
- `CONVENTIONS.md` - Code style, error handling, logging patterns
- `TESTING.md` - Test framework, mocking, fixtures, patterns
- `INTEGRATIONS.md` - External services (self-contained, no external APIs)
- `CONCERNS.md` - Technical debt, security considerations, test gaps

## Project Layout

```
cmd/           CLI commands (cobra) - send, recv, serve, provision, login, init, team, admin, status
internal/
  auth/        Argon2id password hashing
  server/      HTTP server, handlers, middleware, routes
  store/       Store interface + SQLite implementation
    migrations/ Goose SQL migrations (embedded)
web/           Frontend HTML + static assets (embedded in binary)
main.go        Entry point
web.go         go:embed declaration for web/
```

## Build & Run

```bash
go build -o sneaker .           # Build binary
go run . serve                  # Run server (port 7657)
go run . serve --dev            # Dev mode (serve frontend from disk)
go run . serve --port 3000      # Custom port
go run . serve --db my.db       # Custom database path
go run . provision              # Bootstrap: server + admin account + team in one step
```

## Test

```bash
go test ./...                   # Run all tests
go test -v ./internal/server/   # Verbose server tests
go test -cover ./...            # With coverage
go test -race ./...             # Race detector
```

## Key Technical Decisions

- **Pure Go SQLite** (`modernc.org/sqlite`) - no CGo, easy cross-compilation
- **AGE encryption** (`filippo.io/age`) - X25519 for identity mode, scrypt for passphrase protection
- **Embedded assets** - web frontend and SQL migrations embedded via `go:embed`
- **Dual connection pools** - 1 writer + 10 readers for SQLite concurrency (WAL mode)
- **No external services** - fully self-contained, no Redis/Postgres/external APIs
- **Session auth** - 32-byte random tokens, SHA-256 hashed, stored in SQLite
- **CSRF protection** - Go 1.22+ Fetch Metadata via `http.NewCrossOriginProtection()`

## Conventions

- Handlers: `handle{Action}` methods on `*Server` (e.g., `handleCreateSecret`)
- Store files: `sqlite_{domain}.go` (e.g., `sqlite_secrets.go`, `sqlite_auth.go`)
- Errors: sentinel errors with `Err` prefix (e.g., `ErrSecretGone`)
- Tests: co-located `*_test.go`, use `testify` assert/require
- Logging: `log/slog` structured logging with key-value pairs
- Migrations: sequential `NNN_description.sql` with goose up/down

## Secret Modes

1. **Link mode** (default): Ephemeral X25519 keypair, private key in URL fragment, anyone with link can decrypt
2. **Identity mode** (`--to`): Encrypts to recipient's registered public key, requires `sneaker recv` with local identity key
3. **Passphrase protection** (optional): Additional scrypt encryption layer on top of either mode

## API Routes

All routes defined in `internal/server/routes.go`. Auth endpoints are public; most others require `Bearer` token or `sneaker_session` cookie.
