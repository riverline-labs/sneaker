package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// CreateUser inserts a new user and returns the created record.
func (s *SQLiteStore) CreateUser(ctx context.Context, email, passwordHash string) (*User, error) {
	var u User
	var createdAt string
	err := s.writeDB.QueryRowContext(ctx,
		`INSERT INTO users (email, password_hash) VALUES (?, ?)
		 RETURNING id, email, password_hash, created_at`,
		email, passwordHash,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}
	u.CreatedAt, err = time.Parse("2006-01-02 15:04:05", createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}
	return &u, nil
}

// GetUserByEmail retrieves a user by email address.
func (s *SQLiteStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var u User
	var createdAt string
	err := s.readDB.QueryRowContext(ctx,
		`SELECT id, email, password_hash, created_at FROM users WHERE email = ?`,
		email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found: %w", err)
		}
		return nil, fmt.Errorf("getting user by email: %w", err)
	}
	u.CreatedAt, err = time.Parse("2006-01-02 15:04:05", createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}
	return &u, nil
}

// UpdateUserPassword updates the password hash for the user with the given email.
func (s *SQLiteStore) UpdateUserPassword(ctx context.Context, email, passwordHash string) error {
	result, err := s.writeDB.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE email = ?`,
		passwordHash, email,
	)
	if err != nil {
		return fmt.Errorf("updating password: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("user not found: %s", email)
	}
	return nil
}

// CreateSession stores a new session record. The tokenHash should be a
// SHA-256 hash of the raw session token.
func (s *SQLiteStore) CreateSession(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	_, err := s.writeDB.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)`,
		tokenHash, userID, expiresAt.UTC().Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		return fmt.Errorf("creating session: %w", err)
	}
	return nil
}

// GetUserBySession retrieves the user associated with a valid (non-expired)
// session. Returns an error if the session does not exist or is expired.
func (s *SQLiteStore) GetUserBySession(ctx context.Context, tokenHash string) (*User, error) {
	var u User
	var createdAt string
	err := s.readDB.QueryRowContext(ctx,
		`SELECT u.id, u.email, u.password_hash, u.created_at
		 FROM users u
		 JOIN sessions s ON s.user_id = u.id
		 WHERE s.token_hash = ? AND s.expires_at > datetime('now')`,
		tokenHash,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found or expired: %w", err)
		}
		return nil, fmt.Errorf("getting user by session: %w", err)
	}
	u.CreatedAt, err = time.Parse("2006-01-02 15:04:05", createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}
	return &u, nil
}

// DeleteSession removes a single session by its token hash.
func (s *SQLiteStore) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.writeDB.ExecContext(ctx,
		`DELETE FROM sessions WHERE token_hash = ?`,
		tokenHash,
	)
	if err != nil {
		return fmt.Errorf("deleting session: %w", err)
	}
	return nil
}

// DeleteUserSessions removes all sessions for the user with the given email.
func (s *SQLiteStore) DeleteUserSessions(ctx context.Context, email string) error {
	_, err := s.writeDB.ExecContext(ctx,
		`DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = ?)`,
		email,
	)
	if err != nil {
		return fmt.Errorf("deleting user sessions: %w", err)
	}
	return nil
}

// CleanExpiredSessions removes all expired sessions and returns the count deleted.
func (s *SQLiteStore) CleanExpiredSessions(ctx context.Context) (int64, error) {
	result, err := s.writeDB.ExecContext(ctx,
		`DELETE FROM sessions WHERE expires_at <= datetime('now')`,
	)
	if err != nil {
		return 0, fmt.Errorf("cleaning expired sessions: %w", err)
	}
	return result.RowsAffected()
}
