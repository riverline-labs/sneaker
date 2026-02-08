# Testing Patterns

**Analysis Date:** 2026-02-07

## Test Framework

**Runner:**
- Go standard library `testing` package
- Config: None (uses Go defaults)

**Assertion Library:**
- `github.com/stretchr/testify` v1.11.1
- `assert` for non-fatal assertions
- `require` for fatal assertions (test stops on failure)

**Run Commands:**
```bash
go test ./...              # Run all tests
go test -v ./...           # Verbose output
go test -cover ./...       # With coverage
go test -json ./...        # JSON output
```

## Test File Organization

**Location:**
- Co-located with source files in same package
- Test files adjacent to implementation files

**Naming:**
- Pattern: `*_test.go` (e.g., `auth_test.go`, `server_test.go`, `send_test.go`)
- One test file per source file typically

**Structure:**
```
cmd/
├── send.go
├── send_test.go
├── admin_reset_password.go
└── admin_reset_password_test.go

internal/auth/
├── auth.go
└── auth_test.go

internal/server/
├── server.go
├── server_test.go
├── secret_handlers.go
├── secret_handlers_test.go
├── middleware.go
└── middleware_test.go

internal/store/
├── sqlite.go
├── sqlite_test.go
├── sqlite_secrets.go
└── sqlite_secrets_test.go
```

## Test Structure

**Suite Organization:**
```go
func TestHashPassword(t *testing.T) {
    hash, err := HashPassword("test-password", DefaultParams)
    require.NoError(t, err)
    assert.True(t, strings.HasPrefix(hash, "$argon2id$v=19$"))
}

func TestVerifyPasswordCorrect(t *testing.T) {
    hash, err := HashPassword("test-password", DefaultParams)
    require.NoError(t, err)

    match, err := VerifyPassword("test-password", hash)
    require.NoError(t, err)
    assert.True(t, match)
}

// Table-driven tests for multiple cases
func TestParseTTL(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    time.Duration
        wantErr bool
    }{
        {name: "1 hour", input: "1h", want: 1 * time.Hour},
        {name: "30 minutes", input: "30m", want: 30 * time.Minute},
        {name: "empty string", input: "", wantErr: true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := parseTTL(tt.input)
            if tt.wantErr {
                assert.Error(t, err)
                return
            }
            require.NoError(t, err)
            assert.Equal(t, tt.want, got)
        })
    }
}
```

**Patterns:**
- Use `t.Helper()` in test helper functions to improve error reporting
- Subtests with `t.Run()` for grouping related assertions
- Table-driven tests for exhaustive input/output validation
- Setup/teardown via `t.Cleanup()` for resource cleanup
- `defer` for closing resources (e.g., `defer resp.Body.Close()`)

## Mocking

**Framework:** No external mocking framework

**Patterns:**
```go
// In-memory filesystem for testing web assets
func testWebFS() fstest.MapFS {
    return fstest.MapFS{
        "web/index.html": &fstest.MapFile{
            Data: []byte(`<!DOCTYPE html>...`),
        },
        "web/reveal.html": &fstest.MapFile{
            Data: []byte(`<!DOCTYPE html>...`),
        },
    }
}

// Test server creation helper
func newTestServer(t *testing.T) *httptest.Server {
    t.Helper()
    cfg := server.Config{
        Port:  0,
        Dev:   false,
        WebFS: testWebFS(),
    }
    srv := server.New(cfg, nil)
    return httptest.NewServer(srv.Handler())
}
```

**What to Mock:**
- Filesystem: Use `testing/fstest.MapFS` for in-memory files
- HTTP servers: Use `net/http/httptest` for test servers and recorders
- Store operations: Pass `nil` store when database not needed, or use real SQLite with `t.TempDir()`

**What NOT to Mock:**
- Database: Use real SQLite with temporary files (fast enough for tests)
- Cryptographic operations: Test real implementations
- External dependencies: Real `age` encryption, real Argon2 hashing

## Fixtures and Factories

**Test Data:**
```go
// Helper functions create test resources
func createTestUser(t *testing.T, ts *httptest.Server, email, password string) string {
    t.Helper()
    resp := postJSON(t, ts.URL+"/api/auth/signup", map[string]string{
        "email":    email,
        "password": password,
    }, http.Header{"Accept": []string{"application/json"}})
    result := readJSON(t, resp)
    require.Equal(t, http.StatusCreated, resp.StatusCode)
    token, ok := result["token"].(string)
    require.True(t, ok)
    return token
}

// Store test helper
func newTestStore(t *testing.T) *SQLiteStore {
    t.Helper()
    dbPath := filepath.Join(t.TempDir(), "test.db")
    st, err := NewSQLiteStore(dbPath)
    require.NoError(t, err)
    t.Cleanup(func() { st.Close() })
    return st
}
```

**Location:**
- Helpers defined at package level in `*_test.go` files
- Shared across tests within same package
- Use `t.Helper()` to mark helper functions

## Coverage

**Requirements:** None enforced

**View Coverage:**
```bash
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Test Types

**Unit Tests:**
- Test individual functions in isolation
- Examples: `TestHashPassword`, `TestVerifyPassword`, `TestParseTTL`
- Focus on edge cases and error conditions
- Use table-driven tests for comprehensive input coverage

**Integration Tests:**
- Test HTTP handlers end-to-end with real database
- Examples: `TestHandleCreateSecret`, `TestHandleGetSecret`, `TestGetSecretStatus`
- Use `httptest.Server` for HTTP integration
- Real SQLite database with temporary files
- Test full request/response cycle including JSON encoding/decoding

**E2E Tests:**
- Not detected (no separate E2E framework)

## Common Patterns

**Async Testing:**
```go
func TestConsumeSecretConcurrent(t *testing.T) {
    const goroutines = 10
    results := make(chan *Secret, goroutines)
    errs := make(chan error, goroutines)

    var wg sync.WaitGroup
    wg.Add(goroutines)
    for i := 0; i < goroutines; i++ {
        go func() {
            defer wg.Done()
            sec, err := st.ConsumeSecret(ctx, id)
            if err != nil {
                errs <- err
            } else {
                results <- sec
            }
        }()
    }
    wg.Wait()
    close(results)
    close(errs)

    // Verify exactly one goroutine succeeded
    assert.Equal(t, 1, len(results))
}
```

**Error Testing:**
```go
func TestDecodeInvalidHash(t *testing.T) {
    tests := []struct {
        name string
        hash string
    }{
        {"empty string", ""},
        {"garbage", "not-a-hash"},
        {"bad version", "$argon2id$v=999$m=65536,t=3,p=2$c2FsdA$aGFzaA"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            match, err := VerifyPassword("anything", tt.hash)
            assert.Error(t, err)
            assert.False(t, match)
        })
    }
}
```

**HTTP Testing:**
```go
// Request helper (defined in test files)
func postJSON(t *testing.T, url string, body any, headers ...http.Header) *http.Response {
    t.Helper()
    jsonBody, err := json.Marshal(body)
    require.NoError(t, err)

    req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
    require.NoError(t, err)
    req.Header.Set("Content-Type", "application/json")

    if len(headers) > 0 {
        for k, v := range headers[0] {
            req.Header[k] = v
        }
    }

    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    return resp
}

// Usage
resp := postJSON(t, ts.URL+"/api/secrets", map[string]string{
    "ciphertext": ciphertext,
}, http.Header{"Authorization": []string{"Bearer " + token}})
```

**Database Testing:**
```go
// Use real SQLite with temporary directory
func TestCreateSecret(t *testing.T) {
    st := newTestStore(t)
    ctx := context.Background()

    u, err := st.CreateUser(ctx, "alice@example.com", "hash")
    require.NoError(t, err)

    id, err := st.CreateSecret(ctx, []byte("ciphertext-data"), "link", u.ID, nil, time.Now().Add(24*time.Hour), false)
    require.NoError(t, err)

    assert.Len(t, id, 64)
}
```

**Assertion Patterns:**
- Use `require` for preconditions that must succeed (test stops on failure)
- Use `assert` for test conditions (test continues on failure)
- Always check error conditions explicitly:
  ```go
  require.NoError(t, err)  // Fatal if error
  assert.Error(t, err)     // Non-fatal assertion
  assert.True(t, errors.Is(err, ErrSecretGone))  // Sentinel errors
  ```
- Use descriptive assertion messages for complex checks:
  ```go
  assert.Equal(t, 1, successCount, "exactly one goroutine should get the secret")
  ```

**Cleanup Patterns:**
```go
// Use t.Cleanup for resource cleanup
func newTestStore(t *testing.T) *SQLiteStore {
    t.Helper()
    dbPath := filepath.Join(t.TempDir(), "test.db")
    st, err := NewSQLiteStore(dbPath)
    require.NoError(t, err)
    t.Cleanup(func() { st.Close() })
    return st
}

// Defer for per-test cleanup
resp, err := http.Get(ts.URL + "/api/health")
require.NoError(t, err)
defer resp.Body.Close()
```

---

*Testing analysis: 2026-02-07*
