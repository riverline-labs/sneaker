package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// boolToInt converts a bool to an int for SQLite storage (0 or 1).
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CreateSecret stores an encrypted secret and returns the generated 64-char hex ID.
// recipientID is nil for link-mode secrets and non-nil for identity-mode secrets.
func (s *SQLiteStore) CreateSecret(ctx context.Context, ciphertext []byte, mode string, senderID int64, recipientID *int64, expiresAt time.Time, passphraseProtected bool) (string, error) {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating secret ID: %w", err)
	}
	id := hex.EncodeToString(b)

	_, err := s.writeDB.ExecContext(ctx,
		`INSERT INTO secrets (id, ciphertext, mode, sender_id, recipient_id, expires_at, passphrase_protected) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, ciphertext, mode, senderID, recipientID, expiresAt.UTC().Format("2006-01-02 15:04:05"), boolToInt(passphraseProtected),
	)
	if err != nil {
		return "", fmt.Errorf("creating secret: %w", err)
	}
	return id, nil
}

// ConsumeSecret atomically retrieves and soft-deletes a link-mode secret using a transaction.
// The ciphertext is read first, then the row is updated to NULL ciphertext and set retrieved_at.
// Returns ErrSecretGone if the secret does not exist, was already retrieved, or is expired.
func (s *SQLiteStore) ConsumeSecret(ctx context.Context, id string) (*Secret, error) {
	tx, err := s.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning consume transaction: %w", err)
	}
	defer tx.Rollback()

	var sec Secret
	var createdAt, expiresAt string
	var ppInt int

	err = tx.QueryRowContext(ctx,
		`SELECT id, ciphertext, mode, sender_id, created_at, expires_at, passphrase_protected
		 FROM secrets
		 WHERE id = ? AND recipient_id IS NULL AND retrieved_at IS NULL AND expires_at > datetime('now')`,
		id,
	).Scan(&sec.ID, &sec.Ciphertext, &sec.Mode, &sec.SenderID, &createdAt, &expiresAt, &ppInt)

	if err == sql.ErrNoRows {
		return nil, ErrSecretGone
	}
	if err != nil {
		return nil, fmt.Errorf("consuming secret: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`UPDATE secrets SET retrieved_at = datetime('now'), ciphertext = NULL WHERE id = ?`,
		id,
	)
	if err != nil {
		return nil, fmt.Errorf("soft-deleting secret: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing consume transaction: %w", err)
	}

	sec.PassphraseProtected = ppInt == 1
	sec.CreatedAt, err = time.Parse("2006-01-02 15:04:05", createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}
	sec.ExpiresAt, err = time.Parse("2006-01-02 15:04:05", expiresAt)
	if err != nil {
		return nil, fmt.Errorf("parsing expires_at: %w", err)
	}

	return &sec, nil
}

// GetSecretStatus returns status information for a secret owned by senderID.
// Returns ErrSecretGone if the secret does not exist for that sender.
func (s *SQLiteStore) GetSecretStatus(ctx context.Context, id string, senderID int64) (*SecretStatusInfo, error) {
	var createdAt, expiresAt string
	var retrievedAt sql.NullString

	err := s.readDB.QueryRowContext(ctx,
		`SELECT created_at, expires_at, retrieved_at FROM secrets WHERE id = ? AND sender_id = ?`,
		id, senderID,
	).Scan(&createdAt, &expiresAt, &retrievedAt)

	if err == sql.ErrNoRows {
		return nil, ErrSecretGone
	}
	if err != nil {
		return nil, fmt.Errorf("getting secret status: %w", err)
	}

	info := &SecretStatusInfo{}

	info.CreatedAt, err = time.Parse("2006-01-02 15:04:05", createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}
	info.ExpiresAt, err = time.Parse("2006-01-02 15:04:05", expiresAt)
	if err != nil {
		return nil, fmt.Errorf("parsing expires_at: %w", err)
	}

	// Derive status: retrieved_at set -> "retrieved", expires_at <= now -> "expired", else "pending"
	if retrievedAt.Valid {
		info.Status = "retrieved"
	} else if info.ExpiresAt.Before(time.Now()) {
		info.Status = "expired"
	} else {
		info.Status = "pending"
	}

	return info, nil
}

// CleanExpiredSecrets deletes all expired secrets and soft-deleted secrets
// older than 24 hours. Returns the count deleted.
func (s *SQLiteStore) CleanExpiredSecrets(ctx context.Context) (int64, error) {
	result, err := s.writeDB.ExecContext(ctx,
		`DELETE FROM secrets WHERE expires_at <= datetime('now')
		    OR (retrieved_at IS NOT NULL AND retrieved_at < datetime('now', '-1 day'))`,
	)
	if err != nil {
		return 0, fmt.Errorf("cleaning expired secrets: %w", err)
	}
	return result.RowsAffected()
}
