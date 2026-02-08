# Architecture

**Analysis Date:** 2026-02-07

## Pattern Overview

**Overall:** Layered CLI + HTTP Server Architecture

**Key Characteristics:**
- Go-based monolithic application with distinct CLI and server modes
- Store layer abstracts all data access behind interface
- HTTP handlers delegate to store, no business logic in handlers
- AGE (filippo.io/age) encryption handled entirely in CLI/client layer
- Server only stores encrypted ciphertext, never has access to plaintext

## Layers

**CLI Commands Layer:**
- Purpose: User-facing commands for secret exchange and account management
- Location: `cmd/`
- Contains: Cobra command handlers, encryption/decryption logic, HTTP client calls
- Depends on: `internal/auth` (password hashing), AGE library (encryption), HTTP server API
- Used by: End users via terminal

**HTTP Server Layer:**
- Purpose: REST API and static web frontend serving
- Location: `internal/server/`
- Contains: HTTP handlers, middleware, routing, JSON marshaling
- Depends on: `internal/store` interface
- Used by: CLI commands, web frontend

**Store Layer:**
- Purpose: Data persistence abstraction
- Location: `internal/store/`
- Contains: Store interface definition, SQLite implementation, migrations
- Depends on: SQLite driver, goose migrations
- Used by: HTTP server layer

**Auth Layer:**
- Purpose: Password hashing and verification
- Location: `internal/auth/`
- Contains: Argon2id implementation with PHC format encoding
- Depends on: golang.org/x/crypto
- Used by: CLI commands (password input), server handlers (verification)

**Web Frontend:**
- Purpose: Browser-based UI for secret exchange
- Location: `web/`
- Contains: HTML pages, static assets
- Depends on: Nothing (embedded in binary)
- Used by: End users via browser

## Data Flow

**Link-Mode Secret Send (CLI):**

1. User provides plaintext to `sneaker send` command
2. CLI generates ephemeral X25519 keypair
3. CLI encrypts plaintext to ephemeral recipient
4. CLI POSTs ciphertext to `/api/secrets` with Bearer token
5. Server validates session, stores ciphertext with generated 256-bit ID
6. Server returns secret ID
7. CLI prints URL with ephemeral private key in fragment: `https://server/s/{id}#{key}`

**Link-Mode Secret Retrieval (Web):**

1. User opens URL with secret ID and fragment key
2. Browser loads `web/reveal.html` via GET `/s/{id}`
3. JavaScript extracts secret ID and key from URL
4. JavaScript GETs `/api/secrets/{id}` (no auth required)
5. Server retrieves and soft-deletes ciphertext (atomic operation)
6. JavaScript decrypts ciphertext client-side using fragment key
7. Plaintext displayed in browser, never sent to server

**Identity-Mode Secret Send:**

1. User provides `--to recipient@example.com` flag
2. CLI fetches recipient's public key via GET `/api/identity/pubkey/{email}`
3. CLI encrypts plaintext to recipient's registered public key
4. CLI POSTs ciphertext to `/api/secrets` with `mode: identity` and `recipient_email`
5. Server validates recipient exists and has public key
6. Server stores ciphertext with `recipient_id` foreign key

**Identity-Mode Secret Retrieval:**

1. User runs `sneaker recv` command
2. CLI GETs `/api/secrets/inbox` with Bearer token
3. Server returns list of pending secrets for authenticated user
4. For each secret, CLI DELETEs `/api/secrets/inbox/{id}`
5. Server returns ciphertext (atomic retrieve-and-delete)
6. CLI decrypts ciphertext using local identity key from `~/.config/sneaker/identity.key`
7. Plaintext printed to stdout

**State Management:**
- Sessions: Server-side in `sessions` table, token hash stored, 14-day expiry
- Secrets: Server-side in `secrets` table, soft-deleted on retrieval (ciphertext NULLed)
- Identity keys: Client-side in `~/.config/sneaker/identity.key`, public key uploaded to server
- CLI config: Client-side in `~/.config/sneaker/config.json` (server URL, token, email)

## Key Abstractions

**Store Interface:**
- Purpose: Complete data access contract for server
- Examples: `internal/store/store.go` (interface), `internal/store/sqlite.go` (implementation)
- Pattern: Interface with single SQLite implementation using dual connection pools (read/write)

**Secret:**
- Purpose: Represents an encrypted secret with metadata
- Examples: `internal/store/store.go` (type definition)
- Pattern: Struct with `Ciphertext []byte`, `Mode string`, `SenderID int64`, `RecipientID *int64`, TTL fields

**User:**
- Purpose: Authenticated account holder
- Examples: `internal/store/store.go` (type definition)
- Pattern: Struct with `ID int64`, `Email string`, `PasswordHash string`

**Session:**
- Purpose: Stateful authentication token
- Examples: Stored in `sessions` table, accessed via `GetUserBySession(tokenHash)`
- Pattern: SHA-256 hash of random 32-byte token, mapped to user ID and expiry

**Team:**
- Purpose: Named group of users for group secret sending
- Examples: `internal/store/store.go` (type definition)
- Pattern: Team with members, invite tokens for joining

## Entry Points

**CLI Entry Point:**
- Location: `main.go`
- Triggers: User runs `sneaker` command
- Responsibilities: Inject embedded web filesystem, execute Cobra root command

**HTTP Server Entry Point:**
- Location: `cmd/serve.go` (RunE: runServe)
- Triggers: `sneaker serve` command
- Responsibilities: Initialize SQLite store, start HTTP server, handle graceful shutdown

**Provision Entry Point:**
- Location: `cmd/provision.go` (RunE: runProvision)
- Triggers: `sneaker provision` command
- Responsibilities: Start server, create admin account via signup API, create team, save CLI config, keep running

**HTTP Request Entry Point:**
- Location: `internal/server/routes.go`
- Triggers: Incoming HTTP request
- Responsibilities: Route to handler, apply middleware chain (CSRF, security headers, request logging, auth)

**Database Migration Entry Point:**
- Location: `internal/store/sqlite.go` (NewSQLiteStore)
- Triggers: First database connection
- Responsibilities: Run pending goose migrations from embedded `migrations/*.sql` files

## Error Handling

**Strategy:** Return errors up the stack, log at boundaries (handlers, main)

**Patterns:**
- Store layer returns sentinel errors: `ErrSecretGone`, `ErrPublicKeyNotFound`, `ErrTeamNotFound`, `ErrInviteInvalid`
- Server handlers check for specific errors and map to HTTP status codes
- CLI commands return errors directly, Cobra prints to stderr and exits with code 1
- Timing-safe error responses for secret retrieval (always 410 Gone, never leak existence)
- Constant-time password verification to prevent user enumeration

## Cross-Cutting Concerns

**Logging:** `log/slog` structured logging throughout. Server logs all requests, migrations, cleanup operations. CLI errors print to stderr.

**Validation:**
- Secret ID format: 64 lowercase hex chars via regex `^[0-9a-f]{64}$`
- TTL bounds: 5 minutes minimum, 7 days max (link mode), 30 days max (identity mode)
- Ciphertext size: 2MB max via `http.MaxBytesReader`
- Email normalization: lowercase and trimmed before storage/lookup

**Authentication:**
- Session tokens: 32 random bytes, base64-encoded, SHA-256 hash stored
- Cookies: `sneaker_session` httpOnly, secure (if HTTPS detected), SameSite=Lax
- Bearer tokens: Extracted from `Authorization: Bearer {token}` header (fallback)
- Middleware: `requireAuth` validates session and injects `*store.User` into context

**Security:**
- Passwords: Argon2id with RFC 9106 parameters (64MB memory, 3 iterations, parallelism 2)
- CSRF: Go 1.22+ `http.NewCrossOriginProtection()` via Fetch Metadata headers
- Headers: CSP, X-Frame-Options DENY, X-Content-Type-Options nosniff
- Database: File permissions 0600, WAL mode, foreign keys enforced
- Secrets: 256-bit random IDs (32 bytes hex), soft-delete (NULL ciphertext + retrieved_at timestamp)

---

*Architecture analysis: 2026-02-07*
