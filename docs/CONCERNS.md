# Codebase Concerns

**Analysis Date:** 2026-02-07

## Tech Debt

**Test Binaries Committed:**
- Issue: Three large test binaries are present in the repository root and untracked in git
- Files: `auth.test` (6.1 MB), `server.test` (17 MB), `store.test` (13 MB)
- Impact: Repository pollution, potential confusion about test execution, wasted disk space
- Fix approach: Add `*.test` to `.gitignore` and remove binaries from repository; these are build artifacts that should be regenerated on demand

**No HTTP Client Timeout Configuration:**
- Issue: CLI commands use `http.DefaultClient.Do()` without timeout configuration, which has no default timeout
- Files: `cmd/login.go:62`, `cmd/init.go:103`, `cmd/team_join.go:48`, `cmd/status.go:39`, `cmd/team_members.go:41`, `cmd/send.go:144`, `cmd/recv.go:75`
- Impact: CLI commands can hang indefinitely on slow or unresponsive networks, poor user experience
- Fix approach: Create a shared HTTP client with reasonable timeouts (e.g., 30s) in `cmd/config.go` and reuse across all commands

**Panic in Package Initialization:**
- Issue: `internal/auth/auth.go:50` uses `panic()` in `init()` function to generate dummy hash for timing-attack prevention
- Files: `internal/auth/auth.go:46-51`
- Impact: Application will crash at startup if random number generation fails (extremely rare but ungraceful failure mode)
- Fix approach: Move dummy hash generation to lazy initialization or return error from package functions rather than panicking at startup

**Frontend JavaScript Console Warning:**
- Issue: Team send failures log warnings to console but silently continue
- Files: `web/static/js/send.js:257`
- Impact: Users may not realize some team members didn't receive the secret; silent failures reduce reliability
- Fix approach: Accumulate errors and show summary to user, or add visual feedback for partial failures

**No Request Context Timeouts:**
- Issue: HTTP handlers don't set timeouts on database operations via context
- Files: Most handlers in `internal/server/*_handlers.go`
- Impact: Long-running database queries could block handlers indefinitely; no protection against slow queries
- Fix approach: Wrap handler contexts with `context.WithTimeout` for database operations (e.g., 5-10s)

**Hardcoded Argon2 Parameters:**
- Issue: Password hashing uses hardcoded Argon2 parameters with no runtime adjustment
- Files: `internal/auth/auth.go:33-39`
- Impact: No ability to increase security over time without migration; 64MB memory may be too aggressive for some deployment environments
- Fix approach: Make parameters configurable via environment or command flags; consider storing version in database to support parameter migration

## Known Bugs

**Email Case Sensitivity Inconsistency:**
- Symptoms: Email addresses are lowercased inconsistently across different code paths
- Files: `cmd/send.go` (no lowercasing for recipient lookup), `internal/server/secret_handlers.go:92` (lowercases recipient_email), `internal/server/auth_handlers.go` (lowercases on signup/login)
- Trigger: Sending to recipient with mixed-case email may fail to find user if stored with different case
- Workaround: Users should use consistent casing

**Migration Rollback Data Loss:**
- Symptoms: Migration `006_secret_lifecycle.sql` down migration drops soft-deleted secrets
- Files: `internal/store/migrations/006_secret_lifecycle.sql:38-40`
- Trigger: Running goose down from version 006 to 005
- Workaround: Never downgrade migrations in production; this is a development-only issue

## Security Considerations

**No Rate Limiting:**
- Risk: Authentication endpoints vulnerable to brute force attacks; secret creation vulnerable to spam
- Files: `internal/server/routes.go` (no rate limiting middleware), `internal/server/auth_handlers.go` (login endpoint)
- Current mitigation: Argon2id password hashing makes brute force slow, but no protection at HTTP layer
- Recommendations: Add rate limiting middleware using client IP or session; consider exponential backoff for failed login attempts

**No TLS/HTTPS Enforcement:**
- Risk: Server runs HTTP-only; all traffic including passwords and session tokens sent in cleartext
- Files: `internal/server/server.go:177-188` (explicit warning), `cmd/serve.go` (no TLS configuration)
- Current mitigation: Warning message printed at startup; documentation expects reverse proxy
- Recommendations: Add optional built-in TLS support with Let's Encrypt integration; add HSTS headers when behind reverse proxy

**Session Tokens Never Rotate:**
- Risk: Long-lived session tokens (no expiry shown in code) never refresh; stolen tokens valid until explicit logout
- Files: `internal/server/auth_handlers.go` (session creation), `internal/store/sqlite_auth.go` (session storage)
- Current mitigation: Session cleanup runs every 5 minutes but expiry policy unclear
- Recommendations: Implement session expiry (e.g., 7 days) and rotation on sensitive operations; add "last activity" tracking

**Group Send Exposes Recipient List:**
- Risk: When sending to `@team`, CLI command fetches full team member list including all emails
- Files: `cmd/send.go:302-347`, `web/static/js/send.js:179-269`
- Current mitigation: User must already be team member to view list
- Recommendations: This is working as intended but worth documenting privacy implications

**Database File Permissions:**
- Risk: SQLite database created with 0600 permissions but no runtime verification
- Files: `internal/store/sqlite.go:31-35`
- Current mitigation: File created with restrictive permissions on first run
- Recommendations: Add startup check to verify existing database file permissions; warn if too permissive

**No Input Size Limits on Team Names:**
- Risk: Team names and email addresses not validated for length, could cause display issues
- Files: `internal/server/team_handlers.go`, `internal/server/auth_handlers.go`
- Current mitigation: Database schema may have implicit limits
- Recommendations: Add explicit validation (e.g., team names ≤ 64 chars, emails ≤ 255 chars)

## Performance Bottlenecks

**Secret Cleanup Runs on Fixed Schedule:**
- Problem: Expired secrets cleaned every 5 minutes regardless of volume
- Files: `internal/server/server.go:131-150`
- Cause: Fixed ticker doesn't adapt to workload; cleanup runs even when no secrets to delete
- Improvement path: Add adaptive scheduling based on secret creation rate; skip cleanup if previous run found zero expired secrets

**Synchronous Team Send in Frontend:**
- Problem: Browser sends secrets to team members sequentially, not in parallel
- Files: `web/static/js/send.js:230-264`
- Cause: Promise chain processes team members one at a time
- Improvement path: Use `Promise.all()` with batching (e.g., 5 concurrent requests) to parallelize encryption and sending

**No Database Indices on Sender Queries:**
- Problem: Status lookups and team operations may scan full tables
- Files: `internal/store/sqlite_secrets.go:98` (status query filters by sender_id), `internal/store/migrations/006_secret_lifecycle.sql` (no sender_id index)
- Cause: Missing index on `secrets.sender_id`
- Improvement path: Add migration for `CREATE INDEX idx_secrets_sender_id ON secrets(sender_id)`

**Large Test Binary Builds:**
- Problem: Test binaries total 36MB for relatively small codebase
- Files: Root directory test binaries
- Cause: Go test binaries include full package dependencies and aren't stripped
- Improvement path: Remove test binaries from repository; CI can use `go test` without `-c` flag

## Fragile Areas

**Migration Ordering Dependency:**
- Files: `internal/store/migrations/*.sql`
- Why fragile: Migration 006 rebuilds secrets table, requiring careful ordering; any schema changes must account for existing migrations
- Safe modification: Always add new migrations; never edit existing migrations after they've been applied
- Test coverage: No automated tests verify migration up/down cycles work correctly

**Identity File Parsing:**
- Files: `cmd/recv.go:50-56`, `cmd/init.go` (identity generation)
- Why fragile: Age library identity parsing assumes X25519 format; no validation that file wasn't corrupted
- Safe modification: Add checksum or version marker to identity file; validate format before use
- Test coverage: No tests for corrupted identity files

**Session Token Hashing:**
- Files: `internal/server/auth_handlers.go` (token generation), `internal/server/middleware.go:79` (token hashing for lookup)
- Why fragile: Token hash function not centralized; changing hash algorithm would invalidate all sessions
- Safe modification: Extract hash function to shared utility; version token format for future changes
- Test coverage: Tests exist but don't verify hash consistency across locations

**Frontend Age.js Library:**
- Files: `web/static/js/age.js`
- Why fragile: Large minified JavaScript library loaded directly; no integrity check or version tracking
- Safe modification: Add Subresource Integrity (SRI) hash to script tag; document library version
- Test coverage: No automated tests for age.js encryption/decryption in browser

## Scaling Limits

**SQLite Write Contention:**
- Current capacity: Single writer connection handles all mutations
- Limit: ~1000 writes/second on typical hardware; write-heavy workloads will bottleneck
- Scaling path: Current WAL mode with read pool adequate for small deployments; move to PostgreSQL for high-write scenarios (100+ concurrent users)

**In-Memory Secret Storage:**
- Current capacity: Secrets stored as BLOBs in SQLite; no size limit per secret beyond 2MB request limit
- Limit: 1000 concurrent 1MB secrets = 1GB database; large installations could exhaust disk
- Scaling path: Add cleanup job to purge retrieved secrets sooner; consider object storage for large secrets

**Background Cleanup Goroutines:**
- Current capacity: Three cleanup goroutines run indefinitely with 5-minute tickers
- Limit: No mechanism to detect cleanup failures or increasing lag
- Scaling path: Add monitoring for cleanup job duration and backlog size; alert if cleanup can't keep up

## Dependencies at Risk

**modernc.org/sqlite (Pure Go SQLite):**
- Risk: Less mature than cgo-based mattn/go-sqlite3; potential performance or compatibility issues
- Impact: Core database functionality; breaking changes would affect all data operations
- Migration plan: `modernc.org/sqlite` chosen for easier cross-compilation; fallback to `github.com/mattn/go-sqlite3` requires only import change

**filippo.io/age v1.3.1:**
- Risk: Encryption library on version 1.3.1; major version 2.x could introduce breaking API changes
- Impact: All encryption/decryption would break; secret format might change
- Migration plan: Pin to v1.x; extensive testing required before upgrading; may need dual-version support for secret format migration

**No Vendoring:**
- Risk: Dependencies fetched on build; upstream changes or deletions could break builds
- Impact: Cannot build project if dependencies disappear
- Migration plan: Enable Go modules vendoring with `go mod vendor`; commit vendor directory for reproducible builds

## Missing Critical Features

**No Audit Logging:**
- Problem: No record of who accessed which secrets, when teams were modified, or authentication events
- Blocks: Compliance requirements, security incident investigation, user accountability
- Priority: High for production deployments

**No Secret Revocation:**
- Problem: Senders cannot revoke link-mode secrets after creation
- Blocks: Accidental sends, compromised links, changing access requirements
- Priority: Medium; workaround is short TTLs

**No Admin Dashboard:**
- Problem: No way to view system health, user counts, secret statistics without direct database access
- Blocks: Operations visibility, capacity planning
- Priority: Low; `sqlite3` CLI sufficient for current scale

## Test Coverage Gaps

**Frontend JavaScript Not Tested:**
- What's not tested: All browser-side encryption, form validation, error handling in `web/static/js/*.js`
- Files: `web/static/js/send.js`, `web/static/js/reveal.js`, `web/static/js/auth.js`
- Risk: Encryption logic bugs could cause data loss; authentication flows could fail silently
- Priority: High - encryption correctness is critical

**Migration Rollback Not Tested:**
- What's not tested: Goose down migrations have no automated tests
- Files: `internal/store/migrations/*.sql` (down sections)
- Risk: Schema rollback could lose data or fail to execute
- Priority: Low - rollbacks should never happen in production

**Concurrent Secret Consumption:**
- What's not tested: Race condition where same link-mode secret retrieved by multiple clients simultaneously
- Files: `internal/store/sqlite_secrets.go:42-89`
- Risk: Transaction isolation may allow double-retrieval
- Priority: Medium - test exists (`TestConsumeSecretConcurrent`) but coverage unclear

**HTTP Client Error Handling:**
- What's not tested: Network timeouts, malformed responses, server errors in CLI commands
- Files: `cmd/send.go`, `cmd/recv.go`, `cmd/login.go`, etc.
- Risk: CLI hangs or crashes on network issues
- Priority: Medium - real-world network conditions not simulated

**Passphrase Encryption End-to-End:**
- What's not tested: Full flow of passphrase-protected secrets from CLI send to web reveal
- Files: `cmd/send.go:92-118`, `web/static/js/reveal.js`
- Risk: Decryption could fail if layers not properly nested
- Priority: High - feature recently added (07-04 commit)

---

*Concerns audit: 2026-02-07*
