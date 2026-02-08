package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SetPublicKey registers or replaces the AGE public key for a user.
// Uses INSERT ... ON CONFLICT to upsert.
func (s *SQLiteStore) SetPublicKey(ctx context.Context, userID int64, publicKey string) error {
	_, err := s.writeDB.ExecContext(ctx,
		`INSERT INTO public_keys (user_id, public_key)
		 VALUES (?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET public_key = excluded.public_key`,
		userID, publicKey,
	)
	if err != nil {
		return fmt.Errorf("setting public key: %w", err)
	}
	return nil
}

// GetPublicKey retrieves the AGE public key for a user by ID.
// Returns ErrPublicKeyNotFound if no key is registered.
func (s *SQLiteStore) GetPublicKey(ctx context.Context, userID int64) (string, error) {
	var pubKey string
	err := s.readDB.QueryRowContext(ctx,
		`SELECT public_key FROM public_keys WHERE user_id = ?`,
		userID,
	).Scan(&pubKey)
	if err == sql.ErrNoRows {
		return "", ErrPublicKeyNotFound
	}
	if err != nil {
		return "", fmt.Errorf("getting public key: %w", err)
	}
	return pubKey, nil
}

// GetPublicKeyByEmail retrieves the AGE public key for a user by email.
// Returns ErrPublicKeyNotFound if the user does not exist or has no key registered.
func (s *SQLiteStore) GetPublicKeyByEmail(ctx context.Context, email string) (string, error) {
	var pubKey string
	err := s.readDB.QueryRowContext(ctx,
		`SELECT pk.public_key
		 FROM public_keys pk
		 JOIN users u ON u.id = pk.user_id
		 WHERE u.email = ?`,
		email,
	).Scan(&pubKey)
	if err == sql.ErrNoRows {
		return "", ErrPublicKeyNotFound
	}
	if err != nil {
		return "", fmt.Errorf("getting public key by email: %w", err)
	}
	return pubKey, nil
}

// ListSecretsForRecipient returns metadata for pending identity-mode secrets
// addressed to the given recipient. Only non-expired, non-retrieved secrets are
// returned, ordered by creation time descending (newest first).
func (s *SQLiteStore) ListSecretsForRecipient(ctx context.Context, recipientID int64) ([]SecretMetadata, error) {
	rows, err := s.readDB.QueryContext(ctx,
		`SELECT s.id, u.email, s.created_at
		 FROM secrets s
		 JOIN users u ON u.id = s.sender_id
		 WHERE s.recipient_id = ? AND s.mode = 'identity' AND s.retrieved_at IS NULL AND s.expires_at > datetime('now')
		 ORDER BY s.created_at DESC`,
		recipientID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing secrets for recipient: %w", err)
	}
	defer rows.Close()

	var metas []SecretMetadata
	for rows.Next() {
		var m SecretMetadata
		var createdAt string
		if err := rows.Scan(&m.ID, &m.SenderEmail, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning secret metadata: %w", err)
		}
		m.CreatedAt, err = time.Parse("2006-01-02 15:04:05", createdAt)
		if err != nil {
			return nil, fmt.Errorf("parsing created_at: %w", err)
		}
		metas = append(metas, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating secret metadata: %w", err)
	}
	return metas, nil
}

// ConsumeIdentitySecret atomically retrieves and soft-deletes an identity-mode
// secret, verifying the caller is the intended recipient.
// The ciphertext is read first, then the row is updated to NULL ciphertext and set retrieved_at.
// Returns ErrSecretGone if the secret does not exist, was already retrieved,
// is expired, or the recipientID does not match.
func (s *SQLiteStore) ConsumeIdentitySecret(ctx context.Context, id string, recipientID int64) (*Secret, error) {
	tx, err := s.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning consume identity transaction: %w", err)
	}
	defer tx.Rollback()

	var sec Secret
	var createdAt, expiresAt string
	var ppInt int

	err = tx.QueryRowContext(ctx,
		`SELECT id, ciphertext, mode, sender_id, created_at, expires_at, passphrase_protected
		 FROM secrets
		 WHERE id = ? AND recipient_id = ? AND retrieved_at IS NULL AND expires_at > datetime('now')`,
		id, recipientID,
	).Scan(&sec.ID, &sec.Ciphertext, &sec.Mode, &sec.SenderID, &createdAt, &expiresAt, &ppInt)

	if err == sql.ErrNoRows {
		return nil, ErrSecretGone
	}
	if err != nil {
		return nil, fmt.Errorf("consuming identity secret: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`UPDATE secrets SET retrieved_at = datetime('now'), ciphertext = NULL WHERE id = ?`,
		id,
	)
	if err != nil {
		return nil, fmt.Errorf("soft-deleting identity secret: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing consume identity transaction: %w", err)
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
