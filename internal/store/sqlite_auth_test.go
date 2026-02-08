package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func TestCreateUser(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, "alice@example.com", "$argon2id$v=19$fakehash")
	require.NoError(t, err)

	assert.Greater(t, u.ID, int64(0), "ID should be positive")
	assert.Equal(t, "alice@example.com", u.Email)
	assert.Equal(t, "$argon2id$v=19$fakehash", u.PasswordHash)
}

func TestCreateUserDuplicateEmail(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	_, err := st.CreateUser(ctx, "alice@example.com", "hash1")
	require.NoError(t, err)

	_, err = st.CreateUser(ctx, "alice@example.com", "hash2")
	assert.Error(t, err, "duplicate email should fail")
}

func TestGetUserByEmail(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	created, err := st.CreateUser(ctx, "bob@example.com", "somehash")
	require.NoError(t, err)

	fetched, err := st.GetUserByEmail(ctx, "bob@example.com")
	require.NoError(t, err)

	assert.Equal(t, created.ID, fetched.ID)
	assert.Equal(t, "bob@example.com", fetched.Email)
	assert.Equal(t, "somehash", fetched.PasswordHash)
	assert.False(t, fetched.CreatedAt.IsZero(), "CreatedAt should be set")
}

func TestGetUserByEmailNotFound(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	_, err := st.GetUserByEmail(ctx, "nonexistent@example.com")
	assert.Error(t, err, "should error for nonexistent email")
}

func TestUpdateUserPassword(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	_, err := st.CreateUser(ctx, "carol@example.com", "oldhash")
	require.NoError(t, err)

	err = st.UpdateUserPassword(ctx, "carol@example.com", "newhash")
	require.NoError(t, err)

	fetched, err := st.GetUserByEmail(ctx, "carol@example.com")
	require.NoError(t, err)
	assert.Equal(t, "newhash", fetched.PasswordHash)
}

func TestUpdateUserPasswordNotFound(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	err := st.UpdateUserPassword(ctx, "nonexistent@example.com", "hash")
	assert.Error(t, err, "should error for nonexistent email")
}

func TestCreateAndGetSession(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, "dave@example.com", "hash")
	require.NoError(t, err)

	tokenHash := hashToken("session-token-123")
	expiresAt := time.Now().Add(24 * time.Hour)

	err = st.CreateSession(ctx, u.ID, tokenHash, expiresAt)
	require.NoError(t, err)

	fetched, err := st.GetUserBySession(ctx, tokenHash)
	require.NoError(t, err)
	assert.Equal(t, u.ID, fetched.ID)
	assert.Equal(t, "dave@example.com", fetched.Email)
}

func TestGetSessionExpired(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, "eve@example.com", "hash")
	require.NoError(t, err)

	tokenHash := hashToken("expired-token")
	expiresAt := time.Now().Add(-1 * time.Hour) // already expired

	err = st.CreateSession(ctx, u.ID, tokenHash, expiresAt)
	require.NoError(t, err)

	_, err = st.GetUserBySession(ctx, tokenHash)
	assert.Error(t, err, "expired session should not return a user")
}

func TestDeleteSession(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, "frank@example.com", "hash")
	require.NoError(t, err)

	tokenHash := hashToken("delete-me-token")
	err = st.CreateSession(ctx, u.ID, tokenHash, time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	// Session should exist.
	_, err = st.GetUserBySession(ctx, tokenHash)
	require.NoError(t, err)

	// Delete it.
	err = st.DeleteSession(ctx, tokenHash)
	require.NoError(t, err)

	// Session should be gone.
	_, err = st.GetUserBySession(ctx, tokenHash)
	assert.Error(t, err)
}

func TestDeleteUserSessions(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, "grace@example.com", "hash")
	require.NoError(t, err)

	hash1 := hashToken("token-1")
	hash2 := hashToken("token-2")
	err = st.CreateSession(ctx, u.ID, hash1, time.Now().Add(24*time.Hour))
	require.NoError(t, err)
	err = st.CreateSession(ctx, u.ID, hash2, time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	// Both sessions should exist.
	_, err = st.GetUserBySession(ctx, hash1)
	require.NoError(t, err)
	_, err = st.GetUserBySession(ctx, hash2)
	require.NoError(t, err)

	// Delete all sessions for this user.
	err = st.DeleteUserSessions(ctx, "grace@example.com")
	require.NoError(t, err)

	// Both sessions should be gone.
	_, err = st.GetUserBySession(ctx, hash1)
	assert.Error(t, err)
	_, err = st.GetUserBySession(ctx, hash2)
	assert.Error(t, err)
}

func TestCleanExpiredSessions(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, "heidi@example.com", "hash")
	require.NoError(t, err)

	// Create one expired session and one valid session.
	expiredHash := hashToken("expired-session")
	validHash := hashToken("valid-session")

	err = st.CreateSession(ctx, u.ID, expiredHash, time.Now().Add(-1*time.Hour))
	require.NoError(t, err)
	err = st.CreateSession(ctx, u.ID, validHash, time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	// Clean expired sessions.
	cleaned, err := st.CleanExpiredSessions(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), cleaned, "should clean exactly 1 expired session")

	// Valid session should still exist.
	_, err = st.GetUserBySession(ctx, validHash)
	require.NoError(t, err)

	// Expired session should be gone.
	_, err = st.GetUserBySession(ctx, expiredHash)
	assert.Error(t, err)
}
