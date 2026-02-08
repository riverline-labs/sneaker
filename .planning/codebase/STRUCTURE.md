# Codebase Structure

**Analysis Date:** 2026-02-07

## Directory Layout

```
sneaker/
├── cmd/                 # Cobra CLI commands
├── internal/            # Private application packages
│   ├── auth/            # Password hashing (Argon2id)
│   ├── server/          # HTTP server and handlers
│   └── store/           # Data layer interface and SQLite implementation
│       └── migrations/  # SQL schema migrations (goose)
├── web/                 # Frontend HTML and static assets
│   └── static/          # CSS, JavaScript
│       ├── css/
│       └── js/
├── .planning/           # GSD planning documents
├── main.go              # CLI entry point
├── web.go               # Embedded filesystem declaration
├── go.mod               # Go module definition
├── go.sum               # Dependency checksums
└── *.test               # Compiled test binaries (not committed)
```

## Directory Purposes

**cmd/**
- Purpose: All CLI subcommands (send, recv, serve, provision, login, init, team, admin, status, etc.)
- Contains: Cobra command definitions, flag parsing, CLI-specific logic
- Key files:
  - `root.go`: Root command and Execute() function
  - `serve.go`: HTTP server startup command
  - `provision.go`: One-step bootstrap (server + admin account + team)
  - `send.go`: Secret encryption and upload (link and identity modes)
  - `recv.go`: Identity-mode secret retrieval and decryption
  - `init.go`: AGE keypair generation and registration
  - `login.go`: Authentication and config file creation
  - `config.go`: CLI config file helpers (~/.config/sneaker/config.json)

**internal/auth/**
- Purpose: Password hashing and verification
- Contains: Argon2id implementation with PHC format
- Key files:
  - `auth.go`: HashPassword, VerifyPassword, Params struct
  - `auth_test.go`: Unit tests for hashing and timing attacks

**internal/server/**
- Purpose: HTTP server, routing, handlers, middleware
- Contains: REST API implementation, web frontend serving
- Key files:
  - `server.go`: Server struct, Start() method, background cleanup goroutines
  - `routes.go`: HTTP route registration and health check
  - `middleware.go`: requireAuth, securityHeaders, requestLogger
  - `auth_handlers.go`: Signup, login, logout, /api/auth/me
  - `secret_handlers.go`: Create secret, get secret, get status
  - `identity_handlers.go`: Set/get public keys, inbox listing
  - `team_handlers.go`: Create team, list teams, list members, create invite, join team

**internal/store/**
- Purpose: Data persistence abstraction and SQLite implementation
- Contains: Store interface, SQLite dual-pool implementation, migrations
- Key files:
  - `store.go`: Store interface with all data access methods
  - `sqlite.go`: SQLiteStore struct, NewSQLiteStore, connection pool setup
  - `sqlite_auth.go`: User and session CRUD operations
  - `sqlite_secrets.go`: Secret CRUD and atomic consume operations
  - `sqlite_identity.go`: Public key registration and identity-mode secret listing
  - `sqlite_teams.go`: Team and invite operations
  - `migrations/`: Numbered SQL migration files (001_initial.sql, 002_auth.sql, etc.)

**internal/store/migrations/**
- Purpose: Schema evolution via goose migrations
- Contains: SQL files with up/down migrations
- Key files:
  - `001_initial.sql`: users table
  - `002_auth.sql`: sessions table
  - `003_secrets.sql`: secrets table
  - `004_identity.sql`: public_keys table, identity-mode columns
  - `005_teams.sql`: teams, team_members, invites tables
  - `006_secret_lifecycle.sql`: TTL, passphrase, status columns

**web/**
- Purpose: Frontend HTML templates and static assets
- Contains: HTML pages served by HTTP server
- Key files:
  - `index.html`: Landing page
  - `send.html`: Send secret form
  - `reveal.html`: Retrieve and decrypt secret page
  - `login.html`: Login form
  - `signup.html`: Registration form
  - `static/css/`: Stylesheets
  - `static/js/`: Client-side JavaScript

**.planning/**
- Purpose: GSD planning documents (not runtime code)
- Contains: Milestones, phases, research, codebase analysis
- Key directories:
  - `codebase/`: Architecture and conventions docs
  - `phases/`: Implementation phase plans
  - `milestones/`: High-level project milestones
  - `research/`: Background research and decisions

## Key File Locations

**Entry Points:**
- `main.go`: CLI entry point, embeds web filesystem
- `cmd/serve.go`: HTTP server startup
- `cmd/root.go`: Cobra root command

**Configuration:**
- `go.mod`: Go dependencies (age, cobra, goose, sqlite, argon2, testify)
- `~/.config/sneaker/config.json`: CLI runtime config (server URL, token, email) - not in repo
- `~/.config/sneaker/identity.key`: User's AGE private key - not in repo
- `sneaker.db`: SQLite database file (default location) - not in repo

**Core Logic:**
- `cmd/send.go`: Encryption and secret upload (lines 69-118: encryptLinkMode, lines 167-186: encryptIdentityMode)
- `cmd/recv.go`: Secret retrieval and decryption (lines 135-187: runRecv)
- `internal/server/secret_handlers.go`: Secret storage API (lines 24-154: handleCreateSecret)
- `internal/store/sqlite_secrets.go`: Atomic secret consumption (ConsumeSecret method)
- `internal/auth/auth.go`: Password hashing (lines 54-70: HashPassword, lines 72-84: VerifyPassword)

**Testing:**
- Test files co-located with implementation: `*_test.go` in same package
- Example: `internal/server/auth_handlers_test.go` tests `internal/server/auth_handlers.go`
- Compiled test binaries: `auth.test`, `server.test`, `store.test` (not committed, in root dir)

## Naming Conventions

**Files:**
- Command files: `{command}.go` (e.g., `send.go`, `recv.go`, `login.go`)
- Test files: `{file}_test.go` (e.g., `auth_test.go`, `server_test.go`)
- Handler files: `{domain}_handlers.go` (e.g., `auth_handlers.go`, `secret_handlers.go`)
- Store implementation files: `sqlite_{domain}.go` (e.g., `sqlite_auth.go`, `sqlite_secrets.go`)
- Migrations: `{version}_{description}.sql` (e.g., `001_initial.sql`, `002_auth.sql`)

**Directories:**
- Lowercase, snake_case not used (prefer single words or compound: `store`, `server`, `auth`)
- Private packages: `internal/{package}`
- Public commands: `cmd/{subcommand}.go`

**Packages:**
- Match directory name
- Single-word package names preferred: `auth`, `store`, `server`
- No package name stuttering: `store.Store` not `store.StoreStore`

**Functions:**
- Exported: PascalCase (`HashPassword`, `NewSQLiteStore`, `UserFromContext`)
- Unexported: camelCase (`runServe`, `encryptLinkMode`, `writeJSON`)
- Handler methods: `handle{Action}` (e.g., `handleCreateSecret`, `handleLogin`)
- Middleware: noun or verb (`requireAuth`, `securityHeaders`, `requestLogger`)

**Variables:**
- Exported: PascalCase (`DefaultParams`, `DummyHash`, `ErrSecretGone`)
- Unexported: camelCase (`secretIDPattern`, `minTTLSeconds`)
- Receivers: Single letter or short abbreviation (`s *Server`, `u *User`, `st *SQLiteStore`)

**Types:**
- Exported: PascalCase (`Store`, `Secret`, `User`, `Team`, `Params`)
- Unexported: camelCase (`contextKey`, `statusWriter`, `inboxSecret`)

## Where to Add New Code

**New CLI Command:**
- Primary code: `cmd/{command}.go`
- Register in: `cmd/root.go` (add to init() or rootCmd.AddCommand)
- Tests: `cmd/{command}_test.go`

**New HTTP Endpoint:**
- Handler: `internal/server/{domain}_handlers.go` (add method to *Server)
- Route: `internal/server/routes.go` (add to routes() method)
- Tests: `internal/server/{domain}_handlers_test.go`

**New Database Table/Column:**
- Migration: `internal/store/migrations/{next_version}_{description}.sql`
- Store interface: Add method to `internal/store/store.go`
- SQLite implementation: Add method to `internal/store/sqlite_{domain}.go`
- Tests: `internal/store/sqlite_{domain}_test.go`

**New Middleware:**
- Implementation: `internal/server/middleware.go` (add function returning http.Handler)
- Registration: `internal/server/server.go` (add to handler chain in New())

**New Frontend Page:**
- HTML: `web/{page}.html`
- Route: `internal/server/routes.go` (if special routing needed, otherwise static serve catches)
- Assets: `web/static/css/` or `web/static/js/`

**Utilities:**
- Shared CLI helpers: `cmd/config.go` (config file operations)
- Shared server helpers: `internal/server/` (e.g., `writeJSON`, `extractToken` functions)
- Shared store helpers: `internal/store/store.go` (error sentinels, shared types)

## Special Directories

**internal/**
- Purpose: Go private package convention (cannot be imported by external projects)
- Generated: No
- Committed: Yes

**internal/store/migrations/**
- Purpose: SQL schema evolution via goose
- Generated: No (hand-written)
- Committed: Yes
- Embedded: Yes (via `//go:embed migrations/*.sql`)

**web/**
- Purpose: Frontend assets embedded in binary
- Generated: No (hand-written HTML/CSS/JS)
- Committed: Yes
- Embedded: Yes (via `//go:embed all:web` in web.go)

**.planning/**
- Purpose: GSD planning documents, not runtime code
- Generated: Yes (by GSD commands)
- Committed: Yes
- Runtime relevance: None

**Compiled test binaries (*.test):**
- Purpose: Test executables
- Generated: Yes (by `go test -c`)
- Committed: No (.gitignore excludes)

---

*Structure analysis: 2026-02-07*
