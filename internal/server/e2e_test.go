package server_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// doRequest sends an HTTP request with optional JSON body and headers.
// It supports any HTTP method (GET, PUT, DELETE, etc.) unlike postJSON which is POST-only.
func doRequest(t *testing.T, method, url string, body any, headers http.Header) *http.Response {
	t.Helper()

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// TestE2EIdentityModeSecretExchange exercises the full lifecycle:
// provision two users, form a team, exchange AGE-encrypted secrets via
// identity mode, and verify decryption produces the original plaintext.
func TestE2EIdentityModeSecretExchange(t *testing.T) {
	ts, _ := secretTestServer(t)
	defer ts.Close()

	authHeader := func(token string) http.Header {
		return http.Header{"Authorization": []string{"Bearer " + token}}
	}

	// --- Step 1-2: Create two users ---
	adminToken := createTestUser(t, ts, "admin@acme.com", "password123")
	user2Token := createTestUser(t, ts, "user2@acme.com", "password123")

	// --- Step 3: Admin creates team ---
	resp := postJSON(t, ts.URL+"/api/teams", map[string]string{
		"name": "acme",
	}, authHeader(adminToken))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	teamResult := readJSON(t, resp)
	assert.Equal(t, "acme", teamResult["name"])

	// --- Step 4: Admin creates invite ---
	resp = postJSON(t, ts.URL+"/api/teams/acme/invites", nil, authHeader(adminToken))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	inviteResult := readJSON(t, resp)
	inviteToken, ok := inviteResult["token"].(string)
	require.True(t, ok, "expected invite token")
	require.NotEmpty(t, inviteToken)

	// --- Step 5: User2 joins team ---
	resp = postJSON(t, ts.URL+"/api/teams/join", map[string]string{
		"token": inviteToken,
	}, authHeader(user2Token))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	joinResult := readJSON(t, resp)
	assert.Equal(t, "acme", joinResult["team"])

	// --- Step 6: Both users generate AGE keypairs ---
	adminIdentity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	user2Identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	// --- Step 7: Both upload public keys ---
	resp = doRequest(t, "PUT", ts.URL+"/api/identity/pubkey",
		map[string]string{"public_key": adminIdentity.Recipient().String()},
		authHeader(adminToken))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	resp = doRequest(t, "PUT", ts.URL+"/api/identity/pubkey",
		map[string]string{"public_key": user2Identity.Recipient().String()},
		authHeader(user2Token))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// --- Step 8: Admin looks up user2's public key ---
	resp = doRequest(t, "GET", ts.URL+"/api/identity/pubkey/user2@acme.com",
		nil, authHeader(adminToken))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	pubkeyResult := readJSON(t, resp)
	fetchedPubkey, ok := pubkeyResult["public_key"].(string)
	require.True(t, ok)
	assert.Equal(t, user2Identity.Recipient().String(), fetchedPubkey)

	// --- Step 9: Admin encrypts secret to user2 ---
	plaintext := "launch codes: 42-42-42"

	recipient, err := age.ParseX25519Recipient(fetchedPubkey)
	require.NoError(t, err)

	var ciphertextBuf bytes.Buffer
	writer, err := age.Encrypt(&ciphertextBuf, recipient)
	require.NoError(t, err)
	_, err = writer.Write([]byte(plaintext))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	encodedCiphertext := base64.RawURLEncoding.EncodeToString(ciphertextBuf.Bytes())

	// --- Step 10: Admin posts identity-mode secret ---
	resp = postJSON(t, ts.URL+"/api/secrets", map[string]any{
		"ciphertext":      encodedCiphertext,
		"mode":            "identity",
		"recipient_email": "user2@acme.com",
	}, authHeader(adminToken))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	createResult := readJSON(t, resp)
	secretID, ok := createResult["id"].(string)
	require.True(t, ok)
	assert.Len(t, secretID, 64)

	// --- Step 11: User2 checks inbox ---
	resp = doRequest(t, "GET", ts.URL+"/api/secrets/inbox",
		nil, authHeader(user2Token))
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var inboxItems []map[string]any
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	require.NoError(t, json.Unmarshal(body, &inboxItems))

	require.Len(t, inboxItems, 1, "user2 should have exactly 1 inbox item")
	assert.Equal(t, secretID, inboxItems[0]["id"])
	assert.Equal(t, "admin@acme.com", inboxItems[0]["sender_email"])

	// --- Step 12: User2 consumes secret ---
	resp = doRequest(t, "DELETE", ts.URL+"/api/secrets/inbox/"+secretID,
		nil, authHeader(user2Token))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	consumeResult := readJSON(t, resp)
	consumedCiphertext, ok := consumeResult["ciphertext"].(string)
	require.True(t, ok)

	// --- Step 13: User2 decrypts ---
	decodedCiphertext, err := base64.RawURLEncoding.DecodeString(consumedCiphertext)
	require.NoError(t, err)

	reader, err := age.Decrypt(bytes.NewReader(decodedCiphertext), user2Identity)
	require.NoError(t, err)
	decrypted, err := io.ReadAll(reader)
	require.NoError(t, err)

	// --- Step 14: Assert plaintext matches ---
	assert.Equal(t, plaintext, string(decrypted))

	// --- Verify secret is consumed: inbox should now be empty ---
	resp = doRequest(t, "GET", ts.URL+"/api/secrets/inbox",
		nil, authHeader(user2Token))
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	var emptyInbox []map[string]any
	require.NoError(t, json.Unmarshal(body, &emptyInbox))
	assert.Empty(t, emptyInbox, "inbox should be empty after consuming the secret")
}

// TestE2EIdentityModeWrongRecipientCannotDecrypt verifies that a secret
// encrypted to user2 cannot be decrypted by user3 (different identity key).
func TestE2EIdentityModeWrongRecipientCannotDecrypt(t *testing.T) {
	ts, _ := secretTestServer(t)
	defer ts.Close()

	authHeader := func(token string) http.Header {
		return http.Header{"Authorization": []string{"Bearer " + token}}
	}

	senderToken := createTestUser(t, ts, "sender@corp.com", "password123")
	recipientToken := createTestUser(t, ts, "recipient@corp.com", "password123")

	// Generate keypairs.
	recipientIdentity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	wrongIdentity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	// Recipient uploads their public key.
	resp := doRequest(t, "PUT", ts.URL+"/api/identity/pubkey",
		map[string]string{"public_key": recipientIdentity.Recipient().String()},
		authHeader(recipientToken))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Sender encrypts to recipient's public key.
	plaintext := "top secret data"
	var ciphertextBuf bytes.Buffer
	writer, err := age.Encrypt(&ciphertextBuf, recipientIdentity.Recipient())
	require.NoError(t, err)
	_, err = writer.Write([]byte(plaintext))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	encodedCiphertext := base64.RawURLEncoding.EncodeToString(ciphertextBuf.Bytes())

	// Sender posts identity-mode secret.
	resp = postJSON(t, ts.URL+"/api/secrets", map[string]any{
		"ciphertext":      encodedCiphertext,
		"mode":            "identity",
		"recipient_email": "recipient@corp.com",
	}, authHeader(senderToken))
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	createResult := readJSON(t, resp)
	secretID := createResult["id"].(string)

	// Recipient consumes the secret.
	resp = doRequest(t, "DELETE", ts.URL+"/api/secrets/inbox/"+secretID,
		nil, authHeader(recipientToken))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	consumeResult := readJSON(t, resp)
	consumedCiphertext := consumeResult["ciphertext"].(string)

	decodedCiphertext, err := base64.RawURLEncoding.DecodeString(consumedCiphertext)
	require.NoError(t, err)

	// Try decrypting with the WRONG identity key -- should fail.
	_, err = age.Decrypt(bytes.NewReader(decodedCiphertext), wrongIdentity)
	assert.Error(t, err, "decryption with wrong identity key should fail")

	// Decrypting with the CORRECT identity key should succeed.
	reader, err := age.Decrypt(bytes.NewReader(decodedCiphertext), recipientIdentity)
	require.NoError(t, err)
	decrypted, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, plaintext, string(decrypted))
}
