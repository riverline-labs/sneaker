package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// secretIDPattern matches a valid secret ID: exactly 64 lowercase hex characters.
var secretIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TTL bounds for secret expiry.
const (
	minTTLSeconds     = 300       // 5 minutes
	maxLinkTTLSeconds = 7 * 86400 // 7 days
	maxIDTTLSeconds   = 30 * 86400 // 30 days
)

// handleCreateSecret stores an encrypted secret and returns the generated ID.
// Requires authentication (wrapped in requireAuth middleware).
// Supports two modes:
//   - "link" (default): 24h expiry, no recipient. Retrieved via public GET /api/secrets/{id}.
//   - "identity": 7-day expiry, requires recipient_email. Retrieved via authenticated DELETE /api/secrets/inbox/{id}.
func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	// Limit request body to 2MB (1MB plaintext + AGE overhead + base64 expansion).
	r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)

	var req struct {
		Ciphertext          string `json:"ciphertext"`           // base64-encoded
		Mode                string `json:"mode"`                 // "link" (default) or "identity"
		RecipientEmail      string `json:"recipient_email"`      // required for identity mode
		TTLSeconds          int    `json:"ttl_seconds"`          // optional custom TTL (0 = default)
		PassphraseProtected bool   `json:"passphrase_protected"` // only for link mode
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Detect MaxBytesError specifically for 413.
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ciphertext encoding"})
		return
	}

	if len(ciphertext) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ciphertext cannot be empty"})
		return
	}

	// Default mode to "link" if not specified.
	if req.Mode == "" {
		req.Mode = "link"
	}
	if req.Mode != "link" && req.Mode != "identity" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mode"})
		return
	}

	// Passphrase protection is only available for link-mode secrets.
	if req.PassphraseProtected && req.Mode == "identity" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passphrase protection is only available for link-mode secrets"})
		return
	}

	var recipientID *int64
	var expiresAt time.Time

	switch req.Mode {
	case "identity":
		if req.RecipientEmail == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "recipient_email required for identity mode"})
			return
		}
		email := strings.ToLower(strings.TrimSpace(req.RecipientEmail))

		// Look up recipient user.
		recipientUser, err := s.store.GetUserByEmail(r.Context(), email)
		if err != nil || recipientUser == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "recipient not found"})
			return
		}

		// Verify recipient has a public key registered.
		if _, err := s.store.GetPublicKeyByEmail(r.Context(), email); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "recipient has no public key (they need to run sneaker init)"})
			return
		}

		recipientID = &recipientUser.ID

		// Default 7 days for identity mode.
		if req.TTLSeconds == 0 {
			expiresAt = time.Now().UTC().Add(7 * 24 * time.Hour)
		} else {
			if req.TTLSeconds < minTTLSeconds {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "TTL too short (minimum 5 minutes)"})
				return
			}
			if req.TTLSeconds > maxIDTTLSeconds {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "TTL too long (maximum 30 days for identity mode)"})
				return
			}
			expiresAt = time.Now().UTC().Add(time.Duration(req.TTLSeconds) * time.Second)
		}

	default: // "link"
		// Default 24 hours for link mode.
		if req.TTLSeconds == 0 {
			expiresAt = time.Now().UTC().Add(24 * time.Hour)
		} else {
			if req.TTLSeconds < minTTLSeconds {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "TTL too short (minimum 5 minutes)"})
				return
			}
			if req.TTLSeconds > maxLinkTTLSeconds {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "TTL too long (maximum 7 days for link mode)"})
				return
			}
			expiresAt = time.Now().UTC().Add(time.Duration(req.TTLSeconds) * time.Second)
		}
	}

	id, err := s.store.CreateSecret(r.Context(), ciphertext, req.Mode, user.ID, recipientID, expiresAt, req.PassphraseProtected)
	if err != nil {
		slog.Error("failed to create secret", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	slog.Info("secret created", "mode", req.Mode, "sender_id", user.ID)

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         id,
		"expires_at": expiresAt.Format("2006-01-02T15:04:05Z"),
	})
}

// handleGetSecret retrieves and atomically consumes a secret.
// This endpoint is public (no auth required) -- link-mode retrieval uses the
// 256-bit secret ID as the access token.
func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusGone, map[string]string{"error": "secret not found or already retrieved"})
		return
	}

	// Validate ID format. Return 410 (not 400) to avoid leaking format info.
	if !secretIDPattern.MatchString(id) {
		writeJSON(w, http.StatusGone, map[string]string{"error": "secret not found or already retrieved"})
		return
	}

	secret, err := s.store.ConsumeSecret(r.Context(), id)
	if err != nil {
		// ErrSecretGone, expired, or any other error: uniform 410 response.
		writeJSON(w, http.StatusGone, map[string]string{"error": "secret not found or already retrieved"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ciphertext":           base64.RawURLEncoding.EncodeToString(secret.Ciphertext),
		"mode":                 secret.Mode,
		"passphrase_protected": secret.PassphraseProtected,
	})
}

// handleGetSecretStatus returns status information for a secret owned by the caller.
// Requires authentication (wrapped in requireAuth middleware).
// Returns 404 for secrets not owned by the caller or not found.
func (s *Server) handleGetSecretStatus(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	id := r.PathValue("id")
	if id == "" || !secretIDPattern.MatchString(id) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "secret not found"})
		return
	}

	info, err := s.store.GetSecretStatus(r.Context(), id, user.ID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "secret not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":     info.Status,
		"created_at": info.CreatedAt.Format("2006-01-02T15:04:05Z"),
		"expires_at": info.ExpiresAt.Format("2006-01-02T15:04:05Z"),
	})
}
