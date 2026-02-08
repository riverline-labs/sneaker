# Coding Conventions

**Analysis Date:** 2026-02-07

## Naming Patterns

**Files:**
- Source files: lowercase with underscores for multi-word files (e.g., `secret_handlers.go`, `admin_reset_password.go`)
- Test files: `*_test.go` suffix, matching the source file name
- Main entry point: `main.go` in project root

**Functions:**
- Exported functions: PascalCase (e.g., `HashPassword`, `CreateUser`, `ConsumeSecret`)
- Private functions: camelCase (e.g., `encryptLinkMode`, `postSecret`, `newTestStore`)
- Handler functions: camelCase with `handle` prefix (e.g., `handleHealth`, `handleSignup`, `handleCreateSecret`)
- Test functions: PascalCase with `Test` prefix (e.g., `TestHashPassword`, `TestCreateSecret`)
- Helper functions in tests: camelCase with descriptive names (e.g., `newTestServer`, `createTestUser`, `testWebFS`)

**Variables:**
- Local variables: camelCase (e.g., `ciphertext`, `plaintext`, `secretID`)
- Package-level variables: PascalCase for exported (e.g., `DefaultParams`, `DummyHash`), camelCase for private
- Error variables: PascalCase with `Err` prefix (e.g., `ErrInvalidHash`, `ErrSecretGone`, `ErrPublicKeyNotFound`)
- Constants: PascalCase for exported values

**Types:**
- Structs: PascalCase (e.g., `Server`, `Config`, `Secret`, `User`, `Params`)
- Interfaces: PascalCase (e.g., `Store`)
- Struct fields: PascalCase for exported, camelCase for private (e.g., `ID`, `Ciphertext`, `config`, `httpServer`)

## Code Style

**Formatting:**
- Standard Go formatting via `gofmt` (enforced by Go toolchain)
- Indentation: tabs (Go default)
- Line length: no hard limit, but functions kept readable (largest file is 474 lines)

**Linting:**
- No explicit linter configuration detected
- Code follows standard Go conventions and idioms

## Import Organization

**Order:**
1. Standard library imports (e.g., `context`, `fmt`, `net/http`)
2. External dependencies (e.g., `filippo.io/age`, `github.com/spf13/cobra`, `github.com/stretchr/testify`)
3. Internal packages (e.g., `sneaker/internal/auth`, `sneaker/internal/server`, `sneaker/internal/store`)

**Path Aliases:**
- Module name: `sneaker`
- Internal packages use absolute imports: `sneaker/internal/server`, `sneaker/internal/store`, `sneaker/internal/auth`
- No relative imports used

## Error Handling

**Patterns:**
- Errors are returned as the last return value
- Sentinel errors defined as package-level variables with `Err` prefix (e.g., `ErrInvalidHash`, `ErrSecretGone`)
- Error wrapping with `fmt.Errorf` and `%w` verb for context:
  ```go
  return fmt.Errorf("generating salt: %w", err)
  return fmt.Errorf("creating request: %w", err)
  ```
- HTTP handlers return errors via JSON responses with `{"error": "message"}` structure
- Database operations check errors immediately and return early
- Panics reserved for initialization failures only:
  ```go
  if err != nil {
      panic("failed to generate dummy hash: " + err.Error())
  }
  ```

**Error checking:**
- Always check errors before using return values
- Use `errors.Is()` for sentinel error comparisons
- No naked returns; always explicit error returns

## Logging

**Framework:** Standard library `log/slog`

**Patterns:**
- Structured logging with key-value pairs:
  ```go
  slog.Info("starting sneaker server", "addr", s.httpServer.Addr)
  slog.Error("session cleanup failed", "error", err)
  slog.Warn("server running without TLS", "action_required", "deploy behind TLS-terminating reverse proxy")
  ```
- Log levels: `Info`, `Warn`, `Error`
- Database migration logs include version, path, and duration
- Cleanup operations log counts when non-zero
- No debug logging detected

**When to log:**
- Server startup/shutdown
- Background cleanup operations (sessions, secrets, invites)
- Migration application
- Errors in background goroutines
- Security warnings (e.g., missing TLS)

## Comments

**When to Comment:**
- All exported functions, types, and variables have doc comments
- Doc comments are full sentences starting with the symbol name:
  ```go
  // HashPassword returns an encoded Argon2id hash string in PHC format:
  // VerifyPassword performs constant-time comparison of password against an encoded Argon2id hash.
  ```
- Inline comments explain non-obvious behavior:
  ```go
  // Close finalizes encryption and writes the AEAD tag. Must check error.
  // Exactly one goroutine should succeed.
  // CSRF protection via Fetch Metadata: outermost middleware.
  ```
- Security-sensitive code includes rationale:
  ```go
  // DummyHash is a pre-computed Argon2id hash used when a user is not found during login.
  // This ensures login attempts for nonexistent users take the same time as attempts for real users.
  ```

**JSDoc/TSDoc:**
- Not applicable (Go codebase)
- Go doc comments follow standard conventions

## Function Design

**Size:**
- Functions kept focused and readable (typically 10-50 lines)
- Largest functions around 100 lines (e.g., `runSend` at 125 lines, `groupSend` at 43 lines)
- Helper functions extracted for clarity (e.g., `encryptLinkMode`, `postSecret`, `fetchRecipientKey`)

**Parameters:**
- Use structs for configuration (e.g., `Config`, `Params`)
- Pass `context.Context` as first parameter for operations that need it
- Accept interfaces for testability (e.g., `Store` interface)
- Use pointers for optional parameters (e.g., `recipientID *int64`)

**Return Values:**
- Multiple returns common: `(value, error)` pattern
- Use named return values sparingly, only for clarity in complex functions
- Explicit returns preferred over naked returns

## Module Design

**Exports:**
- Clear package boundaries: `internal/auth`, `internal/server`, `internal/store`
- Interfaces define contracts (e.g., `Store` interface in `internal/store/store.go`)
- Only necessary symbols exported (e.g., handler functions are private)

**Barrel Files:**
- Not applicable (Go doesn't use barrel files)
- Package exports controlled via capitalization

**Package Structure:**
- `cmd/` contains CLI commands (Cobra commands)
- `internal/` contains application code (not importable by external projects)
- `internal/auth` handles password hashing and verification
- `internal/server` handles HTTP routing and handlers
- `internal/store` abstracts database operations via `Store` interface

## Versioning

- Follow [Semantic Versioning](https://semver.org/) (MAJOR.MINOR.PATCH)
- Git tags use `v` prefix: `v1.0.0`, `v0.2.1`
- Version is injected at build time via `-ldflags "-X sneaker/cmd.Version=$(VERSION)"`
- `make build` derives the version from `git describe --tags --always --dirty`
- Override with `make build VERSION=1.2.3`
- Without tags or ldflags, version defaults to `dev`
- Tag releases on `main` only after they're ready to ship

---

*Convention analysis: 2026-02-07*
