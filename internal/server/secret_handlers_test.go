package server_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"sneaker/internal/server"
	"sneaker/internal/store"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secretTestServer creates a test server and returns it along with the underlying store
// so tests can create secrets directly.
func secretTestServer(t *testing.T) (*httptest.Server, store.Store) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := store.NewSQLiteStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { st.Close() })

	cfg := server.Config{
		Port:  0,
		Dev:   true,
		WebFS: fstest.MapFS{"web/index.html": &fstest.MapFile{Data: []byte("<html></html>")}},
	}
	srv := server.New(cfg, st)
	return httptest.NewServer(srv.Handler()), st
}

// createTestUser creates a user via the store and returns a Bearer token.
func createTestUser(t *testing.T, ts *httptest.Server, email, password string) string {
	t.Helper()
	resp := postJSON(t, ts.URL+"/api/auth/signup", map[string]string{
		"email":    email,
		"password": password,
	}, http.Header{"Accept": []string{"application/json"}})
	result := readJSON(t, resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	token, ok := result["token"].(string)
	require.True(t, ok, "expected token in signup response")
	return token
}

func TestHandleCreateSecret(t *testing.T) {
	ts, _ := secretTestServer(t)
	defer ts.Close()

	token := createTestUser(t, ts, "sender@example.com", "password123")

	t.Run("201 Created", func(t *testing.T) {
		ciphertext := base64.RawURLEncoding.EncodeToString([]byte("encrypted-data"))
		resp := postJSON(t, ts.URL+"/api/secrets", map[string]string{
			"ciphertext": ciphertext,
		}, http.Header{"Authorization": []string{"Bearer " + token}})

		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		result := readJSON(t, resp)

		// ID should be 64-char hex.
		id, ok := result["id"].(string)
		require.True(t, ok)
		assert.Len(t, id, 64)
		assert.Regexp(t, `^[0-9a-f]{64}$`, id)

		// expires_at should be present.
		expiresAt, ok := result["expires_at"].(string)
		require.True(t, ok)
		assert.NotEmpty(t, expiresAt)

		// Verify expires_at is roughly 24 hours from now.
		parsed, err := time.Parse("2006-01-02T15:04:05Z", expiresAt)
		require.NoError(t, err)
		assert.WithinDuration(t, time.Now().Add(24*time.Hour), parsed, 5*time.Second)
	})

	t.Run("401 Unauthorized", func(t *testing.T) {
		ciphertext := base64.RawURLEncoding.EncodeToString([]byte("encrypted-data"))
		resp := postJSON(t, ts.URL+"/api/secrets", map[string]string{
			"ciphertext": ciphertext,
		})

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		result := readJSON(t, resp)
		assert.Contains(t, result["error"], "authentication")
	})

	t.Run("400 Empty ciphertext", func(t *testing.T) {
		// base64 of empty bytes is empty string.
		resp := postJSON(t, ts.URL+"/api/secrets", map[string]string{
			"ciphertext": "",
		}, http.Header{"Authorization": []string{"Bearer " + token}})

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		result := readJSON(t, resp)
		assert.Contains(t, result["error"], "ciphertext cannot be empty")
	})

	t.Run("400 Invalid base64", func(t *testing.T) {
		resp := postJSON(t, ts.URL+"/api/secrets", map[string]string{
			"ciphertext": "!!!not-valid-base64!!!",
		}, http.Header{"Authorization": []string{"Bearer " + token}})

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		result := readJSON(t, resp)
		assert.Contains(t, result["error"], "invalid ciphertext encoding")
	})
}

func TestHandleCreateSecretBodyLimit(t *testing.T) {
	ts, _ := secretTestServer(t)
	defer ts.Close()

	token := createTestUser(t, ts, "bigsender@example.com", "password123")

	// Create a body > 2MB.
	bigData := strings.Repeat("A", 3*1024*1024)
	body, err := json.Marshal(map[string]string{"ciphertext": bigData})
	require.NoError(t, err)

	req, err := http.NewRequest("POST", ts.URL+"/api/secrets", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	result := readJSON(t, resp)
	assert.Contains(t, result["error"], "too large")
}

func TestHandleGetSecret(t *testing.T) {
	ts, st := secretTestServer(t)
	defer ts.Close()

	// Create a user and a secret directly via the store.
	user, err := st.CreateUser(t.Context(), "retriever@example.com", "hash")
	require.NoError(t, err)

	originalCiphertext := []byte("super-secret-ciphertext")
	secretID, err := st.CreateSecret(t.Context(), originalCiphertext, "link", user.ID, nil, time.Now().Add(24*time.Hour), false)
	require.NoError(t, err)

	t.Run("200 OK first retrieval", func(t *testing.T) {
		req, err := http.NewRequest("GET", ts.URL+"/api/secrets/"+secretID, nil)
		require.NoError(t, err)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		result := readJSON(t, resp)

		// Decode and verify ciphertext matches original.
		encodedCt, ok := result["ciphertext"].(string)
		require.True(t, ok)
		decoded, err := base64.RawURLEncoding.DecodeString(encodedCt)
		require.NoError(t, err)
		assert.Equal(t, originalCiphertext, decoded)

		// Mode should be "link".
		assert.Equal(t, "link", result["mode"])
	})

	t.Run("410 Gone second retrieval", func(t *testing.T) {
		req, err := http.NewRequest("GET", ts.URL+"/api/secrets/"+secretID, nil)
		require.NoError(t, err)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusGone, resp.StatusCode)
		result := readJSON(t, resp)
		assert.Contains(t, result["error"], "not found or already retrieved")
	})

	t.Run("410 Gone nonexistent ID", func(t *testing.T) {
		// Valid format (64 hex chars) but does not exist.
		fakeID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		req, err := http.NewRequest("GET", ts.URL+"/api/secrets/"+fakeID, nil)
		require.NoError(t, err)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusGone, resp.StatusCode)
		result := readJSON(t, resp)
		assert.Contains(t, result["error"], "not found or already retrieved")
	})

	t.Run("410 Gone bad format", func(t *testing.T) {
		req, err := http.NewRequest("GET", ts.URL+"/api/secrets/short-id", nil)
		require.NoError(t, err)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)

		// Should be 410, NOT 400 -- avoid leaking format info.
		assert.Equal(t, http.StatusGone, resp.StatusCode)
		result := readJSON(t, resp)
		assert.Contains(t, result["error"], "not found or already retrieved")
	})
}

func TestCreateSecretWithTTL(t *testing.T) {
	ts, _ := secretTestServer(t)
	defer ts.Close()

	token := createTestUser(t, ts, "ttl-sender@example.com", "password123")

	ciphertext := base64.RawURLEncoding.EncodeToString([]byte("ttl-data"))

	t.Run("custom TTL 1 hour", func(t *testing.T) {
		resp := postJSON(t, ts.URL+"/api/secrets", map[string]any{
			"ciphertext":  ciphertext,
			"ttl_seconds": 3600,
		}, http.Header{"Authorization": []string{"Bearer " + token}})

		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		result := readJSON(t, resp)

		expiresAt, ok := result["expires_at"].(string)
		require.True(t, ok)
		parsed, err := time.Parse("2006-01-02T15:04:05Z", expiresAt)
		require.NoError(t, err)
		assert.WithinDuration(t, time.Now().Add(1*time.Hour), parsed, 5*time.Second)
	})

	t.Run("default TTL when omitted", func(t *testing.T) {
		resp := postJSON(t, ts.URL+"/api/secrets", map[string]any{
			"ciphertext": ciphertext,
		}, http.Header{"Authorization": []string{"Bearer " + token}})

		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		result := readJSON(t, resp)

		expiresAt, ok := result["expires_at"].(string)
		require.True(t, ok)
		parsed, err := time.Parse("2006-01-02T15:04:05Z", expiresAt)
		require.NoError(t, err)
		// Default link mode = 24 hours.
		assert.WithinDuration(t, time.Now().Add(24*time.Hour), parsed, 5*time.Second)
	})
}

func TestCreateSecretTTLTooShort(t *testing.T) {
	ts, _ := secretTestServer(t)
	defer ts.Close()

	token := createTestUser(t, ts, "ttl-short@example.com", "password123")

	ciphertext := base64.RawURLEncoding.EncodeToString([]byte("short-ttl"))
	resp := postJSON(t, ts.URL+"/api/secrets", map[string]any{
		"ciphertext":  ciphertext,
		"ttl_seconds": 60, // 1 minute, below 5-minute minimum
	}, http.Header{"Authorization": []string{"Bearer " + token}})

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	result := readJSON(t, resp)
	assert.Contains(t, result["error"], "TTL too short")
}

func TestCreateSecretTTLTooLong(t *testing.T) {
	ts, _ := secretTestServer(t)
	defer ts.Close()

	token := createTestUser(t, ts, "ttl-long@example.com", "password123")

	ciphertext := base64.RawURLEncoding.EncodeToString([]byte("long-ttl"))
	resp := postJSON(t, ts.URL+"/api/secrets", map[string]any{
		"ciphertext":  ciphertext,
		"ttl_seconds": 700000, // > 7 days for link mode
	}, http.Header{"Authorization": []string{"Bearer " + token}})

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	result := readJSON(t, resp)
	assert.Contains(t, result["error"], "TTL too long")
}

func TestCreateSecretPassphraseProtected(t *testing.T) {
	ts, _ := secretTestServer(t)
	defer ts.Close()

	token := createTestUser(t, ts, "pp-sender@example.com", "password123")

	ciphertext := base64.RawURLEncoding.EncodeToString([]byte("pp-data"))
	resp := postJSON(t, ts.URL+"/api/secrets", map[string]any{
		"ciphertext":           ciphertext,
		"passphrase_protected": true,
	}, http.Header{"Authorization": []string{"Bearer " + token}})

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	result := readJSON(t, resp)
	secretID, ok := result["id"].(string)
	require.True(t, ok)

	// GET the secret and verify passphrase_protected is in the response.
	req, err := http.NewRequest("GET", ts.URL+"/api/secrets/"+secretID, nil)
	require.NoError(t, err)
	client := &http.Client{}
	getResp, err := client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, getResp.StatusCode)
	getResult := readJSON(t, getResp)
	assert.Equal(t, true, getResult["passphrase_protected"])
}

func TestCreateSecretPassphraseIdentityMode(t *testing.T) {
	ts, _ := secretTestServer(t)
	defer ts.Close()

	token := createTestUser(t, ts, "pp-identity@example.com", "password123")

	ciphertext := base64.RawURLEncoding.EncodeToString([]byte("pp-identity-data"))
	resp := postJSON(t, ts.URL+"/api/secrets", map[string]any{
		"ciphertext":           ciphertext,
		"mode":                 "identity",
		"recipient_email":      "someone@example.com",
		"passphrase_protected": true,
	}, http.Header{"Authorization": []string{"Bearer " + token}})

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	result := readJSON(t, resp)
	assert.Contains(t, result["error"], "passphrase protection is only available for link-mode secrets")
}

func TestGetSecretStatus(t *testing.T) {
	ts, st := secretTestServer(t)
	defer ts.Close()

	token := createTestUser(t, ts, "status-sender@example.com", "password123")

	// Create a secret via the API.
	ciphertext := base64.RawURLEncoding.EncodeToString([]byte("status-data"))
	createResp := postJSON(t, ts.URL+"/api/secrets", map[string]any{
		"ciphertext": ciphertext,
	}, http.Header{"Authorization": []string{"Bearer " + token}})
	require.Equal(t, http.StatusCreated, createResp.StatusCode)
	createResult := readJSON(t, createResp)
	secretID := createResult["id"].(string)

	// Suppress unused variable warning for st.
	_ = st

	t.Run("pending status", func(t *testing.T) {
		req, err := http.NewRequest("GET", ts.URL+"/api/secrets/"+secretID+"/status", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		result := readJSON(t, resp)
		assert.Equal(t, "pending", result["status"])
		assert.NotEmpty(t, result["created_at"])
		assert.NotEmpty(t, result["expires_at"])
	})

	t.Run("retrieved status after consume", func(t *testing.T) {
		// Consume the secret via GET /api/secrets/{id}.
		consumeReq, err := http.NewRequest("GET", ts.URL+"/api/secrets/"+secretID, nil)
		require.NoError(t, err)
		client := &http.Client{}
		consumeResp, err := client.Do(consumeReq)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, consumeResp.StatusCode)
		consumeResp.Body.Close()

		// Now check status -- should be "retrieved".
		statusReq, err := http.NewRequest("GET", ts.URL+"/api/secrets/"+secretID+"/status", nil)
		require.NoError(t, err)
		statusReq.Header.Set("Authorization", "Bearer "+token)
		statusResp, err := client.Do(statusReq)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, statusResp.StatusCode)
		result := readJSON(t, statusResp)
		assert.Equal(t, "retrieved", result["status"])
	})
}

func TestGetSecretStatusUnauthorized(t *testing.T) {
	ts, _ := secretTestServer(t)
	defer ts.Close()

	tokenA := createTestUser(t, ts, "status-a@example.com", "password123")
	tokenB := createTestUser(t, ts, "status-b@example.com", "password123")

	// Create secret as user A.
	ciphertext := base64.RawURLEncoding.EncodeToString([]byte("unauth-status"))
	createResp := postJSON(t, ts.URL+"/api/secrets", map[string]any{
		"ciphertext": ciphertext,
	}, http.Header{"Authorization": []string{"Bearer " + tokenA}})
	require.Equal(t, http.StatusCreated, createResp.StatusCode)
	createResult := readJSON(t, createResp)
	secretID := createResult["id"].(string)

	// Try to get status as user B -- should return 404.
	req, err := http.NewRequest("GET", ts.URL+"/api/secrets/"+secretID+"/status", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokenB)

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	result := readJSON(t, resp)
	assert.Contains(t, result["error"], "secret not found")
}

func TestGetSecretStatusNotFound(t *testing.T) {
	ts, _ := secretTestServer(t)
	defer ts.Close()

	token := createTestUser(t, ts, "status-nf@example.com", "password123")

	// Invalid format ID.
	req, err := http.NewRequest("GET", ts.URL+"/api/secrets/bad-id/status", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	result := readJSON(t, resp)
	assert.Contains(t, result["error"], "secret not found")

	// Valid format but nonexistent.
	fakeID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	req2, err := http.NewRequest("GET", ts.URL+"/api/secrets/"+fakeID+"/status", nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+token)

	resp2, err := client.Do(req2)
	require.NoError(t, err)

	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)
	result2 := readJSON(t, resp2)
	assert.Contains(t, result2["error"], "secret not found")
}

func TestHandleGetSecretNoAuth(t *testing.T) {
	ts, st := secretTestServer(t)
	defer ts.Close()

	// Create a user and a secret directly via the store.
	user, err := st.CreateUser(t.Context(), "public@example.com", "hash")
	require.NoError(t, err)

	secretID, err := st.CreateSecret(t.Context(), []byte("public-ciphertext"), "link", user.ID, nil, time.Now().Add(24*time.Hour), false)
	require.NoError(t, err)

	// GET without any auth header -- should succeed (link-mode is public).
	req, err := http.NewRequest("GET", ts.URL+"/api/secrets/"+secretID, nil)
	require.NoError(t, err)

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	result := readJSON(t, resp)
	assert.NotEmpty(t, result["ciphertext"])
	assert.Equal(t, "link", result["mode"])
}
