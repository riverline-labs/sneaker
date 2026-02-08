package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// CreateTeam atomically creates a team and adds the creator as owner.
func (s *SQLiteStore) CreateTeam(ctx context.Context, name string, creatorID int64) (*Team, error) {
	tx, err := s.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	var team Team
	var createdAt string
	err = tx.QueryRowContext(ctx,
		`INSERT INTO teams (name, creator_id) VALUES (?, ?)
		 RETURNING id, name, creator_id, created_at`,
		name, creatorID,
	).Scan(&team.ID, &team.Name, &team.CreatorID, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("creating team: %w", err)
	}

	team.CreatedAt, err = time.Parse("2006-01-02 15:04:05", createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, 'owner')`,
		team.ID, creatorID,
	)
	if err != nil {
		return nil, fmt.Errorf("adding creator as owner: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing transaction: %w", err)
	}

	return &team, nil
}

// GetTeamByName retrieves a team by its case-insensitive name.
// Returns ErrTeamNotFound if the team does not exist.
func (s *SQLiteStore) GetTeamByName(ctx context.Context, name string) (*Team, error) {
	var team Team
	var createdAt string
	err := s.readDB.QueryRowContext(ctx,
		`SELECT id, name, creator_id, created_at FROM teams WHERE name = ?`,
		name,
	).Scan(&team.ID, &team.Name, &team.CreatorID, &createdAt)
	if err == sql.ErrNoRows {
		return nil, ErrTeamNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting team by name: %w", err)
	}

	team.CreatedAt, err = time.Parse("2006-01-02 15:04:05", createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}

	return &team, nil
}

// IsTeamMember checks whether a user is a member of the given team.
func (s *SQLiteStore) IsTeamMember(ctx context.Context, teamID, userID int64) (bool, error) {
	var exists int
	err := s.readDB.QueryRowContext(ctx,
		`SELECT 1 FROM team_members WHERE team_id = ? AND user_id = ?`,
		teamID, userID,
	).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking team membership: %w", err)
	}
	return true, nil
}

// ListTeamMembers returns all members of a team with their email, public key, and role.
// Owners sort first (alphabetically 'owner' > 'member'), then by email.
func (s *SQLiteStore) ListTeamMembers(ctx context.Context, teamID int64) ([]TeamMember, error) {
	rows, err := s.readDB.QueryContext(ctx,
		`SELECT u.email, COALESCE(pk.public_key, '') AS public_key, tm.role
		 FROM team_members tm
		 JOIN users u ON u.id = tm.user_id
		 LEFT JOIN public_keys pk ON pk.user_id = tm.user_id
		 WHERE tm.team_id = ?
		 ORDER BY tm.role DESC, u.email ASC`,
		teamID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing team members: %w", err)
	}
	defer rows.Close()

	members := make([]TeamMember, 0)
	for rows.Next() {
		var m TeamMember
		if err := rows.Scan(&m.Email, &m.PublicKey, &m.Role); err != nil {
			return nil, fmt.Errorf("scanning team member: %w", err)
		}
		members = append(members, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating team members: %w", err)
	}
	return members, nil
}

// ListUserTeams returns all teams that the user is a member of, ordered by name.
func (s *SQLiteStore) ListUserTeams(ctx context.Context, userID int64) ([]Team, error) {
	rows, err := s.readDB.QueryContext(ctx,
		`SELECT t.id, t.name, t.creator_id, t.created_at
		 FROM teams t
		 JOIN team_members tm ON tm.team_id = t.id
		 WHERE tm.user_id = ?
		 ORDER BY t.name ASC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing user teams: %w", err)
	}
	defer rows.Close()

	teams := make([]Team, 0)
	for rows.Next() {
		var t Team
		var createdAt string
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatorID, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning team: %w", err)
		}
		t.CreatedAt, err = time.Parse("2006-01-02 15:04:05", createdAt)
		if err != nil {
			return nil, fmt.Errorf("parsing created_at: %w", err)
		}
		teams = append(teams, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating teams: %w", err)
	}
	return teams, nil
}

// CreateInvite generates a single-use invite token for the given team.
func (s *SQLiteStore) CreateInvite(ctx context.Context, teamID, createdBy int64, expiresAt time.Time) (string, error) {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating invite token: %w", err)
	}
	token := hex.EncodeToString(b)

	_, err := s.writeDB.ExecContext(ctx,
		`INSERT INTO team_invites (token, team_id, created_by, expires_at) VALUES (?, ?, ?, ?)`,
		token, teamID, createdBy, expiresAt.UTC().Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		return "", fmt.Errorf("creating invite: %w", err)
	}
	return token, nil
}

// RedeemInvite atomically consumes an invite token and adds the user as a member.
// Returns the team name on success, or ErrInviteInvalid if the token is invalid or expired.
func (s *SQLiteStore) RedeemInvite(ctx context.Context, token string, userID int64) (string, error) {
	tx, err := s.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	var teamID int64
	err = tx.QueryRowContext(ctx,
		`DELETE FROM team_invites WHERE token = ? AND expires_at > datetime('now')
		 RETURNING team_id`,
		token,
	).Scan(&teamID)
	if err == sql.ErrNoRows {
		return "", ErrInviteInvalid
	}
	if err != nil {
		return "", fmt.Errorf("consuming invite: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO team_members (team_id, user_id, role) VALUES (?, ?, 'member')`,
		teamID, userID,
	)
	if err != nil {
		return "", fmt.Errorf("adding team member: %w", err)
	}

	var teamName string
	err = tx.QueryRowContext(ctx,
		`SELECT name FROM teams WHERE id = ?`,
		teamID,
	).Scan(&teamName)
	if err != nil {
		return "", fmt.Errorf("getting team name: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("committing transaction: %w", err)
	}

	return teamName, nil
}

// CleanExpiredInvites removes all expired invite tokens and returns the count deleted.
func (s *SQLiteStore) CleanExpiredInvites(ctx context.Context) (int64, error) {
	result, err := s.writeDB.ExecContext(ctx,
		`DELETE FROM team_invites WHERE expires_at <= datetime('now')`,
	)
	if err != nil {
		return 0, fmt.Errorf("cleaning expired invites: %w", err)
	}
	return result.RowsAffected()
}
