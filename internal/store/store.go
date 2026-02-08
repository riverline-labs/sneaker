package store

import (
	"context"
	"errors"
	"time"
)

// ErrSecretGone indicates that a secret does not exist, was already retrieved,
// or has expired.
var ErrSecretGone = errors.New("secret not found or already retrieved")

// ErrPublicKeyNotFound indicates that no public key is registered for the user.
var ErrPublicKeyNotFound = errors.New("public key not found")

// ErrTeamNotFound indicates that the requested team does not exist.
var ErrTeamNotFound = errors.New("team not found")

// ErrInviteInvalid indicates that the invite token is invalid or expired.
var ErrInviteInvalid = errors.New("invite token invalid or expired")

// ErrNotTeamMember indicates that the user is not a member of the team.
var ErrNotTeamMember = errors.New("not a team member")

// Secret represents an encrypted secret stored on the server.
type Secret struct {
	ID                   string
	Ciphertext           []byte
	Mode                 string // "link" or "identity"
	SenderID             int64
	CreatedAt            time.Time
	ExpiresAt            time.Time
	PassphraseProtected  bool
}

// SecretStatusInfo contains status information for a secret owned by the caller.
type SecretStatusInfo struct {
	Status    string    // "pending", "retrieved", "expired"
	CreatedAt time.Time
	ExpiresAt time.Time
}

// User represents an authenticated user account.
type User struct {
	ID           int64
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

// SecretMetadata contains non-sensitive metadata about a pending secret.
type SecretMetadata struct {
	ID          string
	SenderEmail string
	CreatedAt   time.Time
}

// Team represents a named group of users.
type Team struct {
	ID        int64
	Name      string
	CreatorID int64
	CreatedAt time.Time
}

// TeamMember represents a user's membership in a team.
type TeamMember struct {
	Email     string
	PublicKey string // empty string if user hasn't run sneaker init
	Role      string // "owner" or "member"
}

// Store defines the interface for all data access.
type Store interface {
	// Close releases database connections. Call once during shutdown.
	Close() error

	// Ping verifies the database is reachable.
	Ping(ctx context.Context) error

	// --- User operations (Phase 2) ---

	// CreateUser inserts a new user with the given email and password hash.
	CreateUser(ctx context.Context, email, passwordHash string) (*User, error)

	// GetUserByEmail retrieves a user by their email address.
	GetUserByEmail(ctx context.Context, email string) (*User, error)

	// UpdateUserPassword updates the password hash for the given email.
	UpdateUserPassword(ctx context.Context, email, passwordHash string) error

	// --- Session operations (Phase 2) ---

	// CreateSession stores a new session. The tokenHash is a SHA-256 hash of
	// the raw session token -- raw tokens are never stored.
	CreateSession(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error

	// GetUserBySession retrieves the user associated with a valid (non-expired)
	// session identified by tokenHash.
	GetUserBySession(ctx context.Context, tokenHash string) (*User, error)

	// DeleteSession removes a single session by its token hash.
	DeleteSession(ctx context.Context, tokenHash string) error

	// DeleteUserSessions removes all sessions for the user with the given email.
	DeleteUserSessions(ctx context.Context, email string) error

	// CleanExpiredSessions removes all expired sessions and returns the count.
	CleanExpiredSessions(ctx context.Context) (int64, error)

	// --- Secret operations (Phase 3) ---

	// CreateSecret stores an encrypted secret and returns the generated ID.
	// recipientID is nil for link-mode secrets and non-nil for identity-mode secrets.
	CreateSecret(ctx context.Context, ciphertext []byte, mode string, senderID int64, recipientID *int64, expiresAt time.Time, passphraseProtected bool) (string, error)

	// ConsumeSecret atomically retrieves and soft-deletes a link-mode secret.
	// The ciphertext is returned and then NULLed in the database; retrieved_at is set.
	// Returns ErrSecretGone if the secret does not exist, was already retrieved, or is expired.
	ConsumeSecret(ctx context.Context, id string) (*Secret, error)

	// GetSecretStatus returns status information for a secret owned by senderID.
	// Returns ErrSecretGone if the secret does not exist for that sender.
	GetSecretStatus(ctx context.Context, id string, senderID int64) (*SecretStatusInfo, error)

	// CleanExpiredSecrets deletes all expired secrets and soft-deleted secrets
	// older than 24 hours. Returns the count deleted.
	CleanExpiredSecrets(ctx context.Context) (int64, error)

	// --- Identity operations (Phase 5) ---

	// SetPublicKey registers or replaces the AGE public key for a user.
	SetPublicKey(ctx context.Context, userID int64, publicKey string) error

	// GetPublicKey retrieves the AGE public key for a user by ID.
	// Returns ErrPublicKeyNotFound if no key is registered.
	GetPublicKey(ctx context.Context, userID int64) (string, error)

	// GetPublicKeyByEmail retrieves the AGE public key for a user by email.
	// Returns ErrPublicKeyNotFound if no key is registered.
	GetPublicKeyByEmail(ctx context.Context, email string) (string, error)

	// ListSecretsForRecipient returns metadata for pending identity-mode secrets
	// addressed to the given recipient.
	ListSecretsForRecipient(ctx context.Context, recipientID int64) ([]SecretMetadata, error)

	// ConsumeIdentitySecret atomically retrieves and soft-deletes an identity-mode
	// secret, verifying the caller is the intended recipient.
	// The ciphertext is returned and then NULLed in the database; retrieved_at is set.
	// Returns ErrSecretGone if the secret does not exist, was already retrieved,
	// is expired, or the recipientID does not match.
	ConsumeIdentitySecret(ctx context.Context, id string, recipientID int64) (*Secret, error)

	// --- Team operations (Phase 6) ---

	// CreateTeam atomically creates a team and adds the creator as owner.
	CreateTeam(ctx context.Context, name string, creatorID int64) (*Team, error)

	// GetTeamByName retrieves a team by its case-insensitive name.
	// Returns ErrTeamNotFound if the team does not exist.
	GetTeamByName(ctx context.Context, name string) (*Team, error)

	// IsTeamMember checks whether a user is a member of the given team.
	IsTeamMember(ctx context.Context, teamID, userID int64) (bool, error)

	// ListTeamMembers returns all members of a team with their email, public key, and role.
	ListTeamMembers(ctx context.Context, teamID int64) ([]TeamMember, error)

	// ListUserTeams returns all teams that the user is a member of.
	ListUserTeams(ctx context.Context, userID int64) ([]Team, error)

	// CreateInvite generates a single-use invite token for the given team.
	CreateInvite(ctx context.Context, teamID, createdBy int64, expiresAt time.Time) (string, error)

	// RedeemInvite atomically consumes an invite token and adds the user as a member.
	// Returns the team name on success, or ErrInviteInvalid if the token is invalid or expired.
	RedeemInvite(ctx context.Context, token string, userID int64) (string, error)

	// CleanExpiredInvites removes all expired invite tokens and returns the count deleted.
	CleanExpiredInvites(ctx context.Context) (int64, error)
}
