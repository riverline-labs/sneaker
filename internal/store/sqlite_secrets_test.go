package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSecret(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, "alice@example.com", "hash")
	require.NoError(t, err)

	id, err := st.CreateSecret(ctx, []byte("ciphertext-data"), "link", u.ID, nil, time.Now().Add(24*time.Hour), false)
	require.NoError(t, err)

	assert.Len(t, id, 64, "ID should be 64-char hex (32 bytes)")
}

func TestConsumeSecret(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, "bob@example.com", "hash")
	require.NoError(t, err)

	ciphertext := []byte("super-secret-ciphertext")
	id, err := st.CreateSecret(ctx, ciphertext, "link", u.ID, nil, time.Now().Add(24*time.Hour), false)
	require.NoError(t, err)

	// First consume should succeed.
	sec, err := st.ConsumeSecret(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, id, sec.ID)
	assert.Equal(t, ciphertext, sec.Ciphertext)
	assert.Equal(t, "link", sec.Mode)
	assert.Equal(t, u.ID, sec.SenderID)
	assert.False(t, sec.CreatedAt.IsZero(), "CreatedAt should be set")
	assert.False(t, sec.ExpiresAt.IsZero(), "ExpiresAt should be set")

	// Second consume should fail with ErrSecretGone (soft-delete: row exists but retrieved_at is set).
	_, err = st.ConsumeSecret(ctx, id)
	assert.True(t, errors.Is(err, ErrSecretGone), "second consume should return ErrSecretGone")
}

func TestConsumeSecretExpired(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, "carol@example.com", "hash")
	require.NoError(t, err)

	// Create a secret that is already expired.
	id, err := st.CreateSecret(ctx, []byte("expired-data"), "link", u.ID, nil, time.Now().Add(-1*time.Hour), false)
	require.NoError(t, err)

	// Consume should fail with ErrSecretGone for expired secret.
	_, err = st.ConsumeSecret(ctx, id)
	assert.True(t, errors.Is(err, ErrSecretGone), "expired secret should return ErrSecretGone")
}

func TestConsumeSecretConcurrent(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, "dave@example.com", "hash")
	require.NoError(t, err)

	id, err := st.CreateSecret(ctx, []byte("race-me"), "link", u.ID, nil, time.Now().Add(24*time.Hour), false)
	require.NoError(t, err)

	// Race 10 goroutines to consume the same secret.
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

	// Exactly one goroutine should succeed.
	var successCount int
	for sec := range results {
		assert.Equal(t, id, sec.ID)
		successCount++
	}
	assert.Equal(t, 1, successCount, "exactly one goroutine should get the secret")

	// All others should get ErrSecretGone.
	var errorCount int
	for err := range errs {
		assert.True(t, errors.Is(err, ErrSecretGone), "losers should get ErrSecretGone, got: %v", err)
		errorCount++
	}
	assert.Equal(t, goroutines-1, errorCount)
}

func TestCleanExpiredSecrets(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, "eve@example.com", "hash")
	require.NoError(t, err)

	// Create one expired secret and one valid secret.
	_, err = st.CreateSecret(ctx, []byte("expired"), "link", u.ID, nil, time.Now().Add(-1*time.Hour), false)
	require.NoError(t, err)

	validID, err := st.CreateSecret(ctx, []byte("still-valid"), "link", u.ID, nil, time.Now().Add(24*time.Hour), false)
	require.NoError(t, err)

	// Clean expired secrets.
	count, err := st.CleanExpiredSecrets(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "should clean exactly 1 expired secret")

	// Valid secret should still be consumable.
	sec, err := st.ConsumeSecret(ctx, validID)
	require.NoError(t, err)
	assert.Equal(t, []byte("still-valid"), sec.Ciphertext)
}

func TestGetSecretStatus(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, "frank@example.com", "hash")
	require.NoError(t, err)

	// Create a secret and check status is "pending".
	id, err := st.CreateSecret(ctx, []byte("status-test"), "link", u.ID, nil, time.Now().Add(24*time.Hour), false)
	require.NoError(t, err)

	info, err := st.GetSecretStatus(ctx, id, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "pending", info.Status)
	assert.False(t, info.CreatedAt.IsZero())
	assert.False(t, info.ExpiresAt.IsZero())

	// Consume it and check status is "retrieved".
	_, err = st.ConsumeSecret(ctx, id)
	require.NoError(t, err)

	info, err = st.GetSecretStatus(ctx, id, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "retrieved", info.Status)

	// Create an expired secret and check status is "expired".
	expiredID, err := st.CreateSecret(ctx, []byte("expired-status"), "link", u.ID, nil, time.Now().Add(-1*time.Hour), false)
	require.NoError(t, err)

	info, err = st.GetSecretStatus(ctx, expiredID, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "expired", info.Status)

	// Unknown ID should return ErrSecretGone.
	_, err = st.GetSecretStatus(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", u.ID)
	assert.True(t, errors.Is(err, ErrSecretGone))
}

func TestCreateSecretPassphraseProtected(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, "grace@example.com", "hash")
	require.NoError(t, err)

	// Create with passphraseProtected=true.
	id, err := st.CreateSecret(ctx, []byte("passphrase-data"), "link", u.ID, nil, time.Now().Add(24*time.Hour), true)
	require.NoError(t, err)

	// Consume and verify PassphraseProtected is true.
	sec, err := st.ConsumeSecret(ctx, id)
	require.NoError(t, err)
	assert.True(t, sec.PassphraseProtected, "PassphraseProtected should be true")
	assert.Equal(t, []byte("passphrase-data"), sec.Ciphertext)

	// Create without passphrase and verify false.
	id2, err := st.CreateSecret(ctx, []byte("no-passphrase"), "link", u.ID, nil, time.Now().Add(24*time.Hour), false)
	require.NoError(t, err)

	sec2, err := st.ConsumeSecret(ctx, id2)
	require.NoError(t, err)
	assert.False(t, sec2.PassphraseProtected, "PassphraseProtected should be false")
}

func TestCleanRetrievedSecrets(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, "heidi@example.com", "hash")
	require.NoError(t, err)

	// Create a secret and consume it (soft-delete).
	id, err := st.CreateSecret(ctx, []byte("cleanup-test"), "link", u.ID, nil, time.Now().Add(24*time.Hour), false)
	require.NoError(t, err)

	_, err = st.ConsumeSecret(ctx, id)
	require.NoError(t, err)

	// Freshly consumed secret should NOT be cleaned (retrieved_at is recent).
	count, err := st.CleanExpiredSecrets(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "freshly consumed secret should not be cleaned")

	// Verify the row still exists by checking status.
	info, err := st.GetSecretStatus(ctx, id, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "retrieved", info.Status)

	// Insert a secret with retrieved_at in the past (>24h ago) directly.
	_, err = st.WriteDB().ExecContext(ctx,
		`INSERT INTO secrets (id, ciphertext, mode, sender_id, expires_at, retrieved_at, passphrase_protected)
		 VALUES ('oldretrieved0000000000000000000000000000000000000000000000000000', NULL, 'link', ?, datetime('now', '+1 day'), datetime('now', '-2 days'), 0)`,
		u.ID,
	)
	require.NoError(t, err)

	// Clean should remove the old retrieved secret.
	count, err = st.CleanExpiredSecrets(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "old retrieved secret should be cleaned")

	// But the recently consumed one should still exist.
	info, err = st.GetSecretStatus(ctx, id, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "retrieved", info.Status)
}
