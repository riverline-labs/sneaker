package server

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"filippo.io/age"
)

// handleSetPublicKey stores or replaces the authenticated user's AGE public key.
// PUT /api/identity/pubkey
func (s *Server) handleSetPublicKey(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.PublicKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "public_key is required"})
		return
	}

	// Validate that the key is a well-formed age X25519 recipient.
	if _, err := age.ParseX25519Recipient(req.PublicKey); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid age public key"})
		return
	}

	if err := s.store.SetPublicKey(r.Context(), user.ID, req.PublicKey); err != nil {
		slog.Error("failed to set public key", "error", err, "user_id", user.ID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	slog.Info("public key set", "user_id", user.ID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleGetPublicKey looks up another user's AGE public key by email.
// GET /api/identity/pubkey/{email}
func (s *Server) handleGetPublicKey(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.PathValue("email")))
	if email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}

	pubKey, err := s.store.GetPublicKeyByEmail(r.Context(), email)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "recipient not found or has no public key"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"public_key": pubKey})
}

// handleListInbox returns metadata for pending identity-mode secrets addressed
// to the authenticated user.
// GET /api/secrets/inbox
func (s *Server) handleListInbox(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	metas, err := s.store.ListSecretsForRecipient(r.Context(), user.ID)
	if err != nil {
		slog.Error("failed to list inbox", "error", err, "user_id", user.ID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	// Build response array; never return null -- always an empty array.
	items := make([]map[string]any, 0, len(metas))
	for _, m := range metas {
		items = append(items, map[string]any{
			"id":           m.ID,
			"sender_email": m.SenderEmail,
			"created_at":   m.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	writeJSON(w, http.StatusOK, items)
}

// handleConsumeInboxSecret atomically retrieves and deletes an identity-mode
// secret addressed to the authenticated user.
// DELETE /api/secrets/inbox/{id}
func (s *Server) handleConsumeInboxSecret(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	id := r.PathValue("id")

	// Validate ID format. Return 410 to avoid leaking format info.
	if !secretIDPattern.MatchString(id) {
		writeJSON(w, http.StatusGone, map[string]string{"error": "secret not found or already retrieved"})
		return
	}

	secret, err := s.store.ConsumeIdentitySecret(r.Context(), id, user.ID)
	if err != nil {
		writeJSON(w, http.StatusGone, map[string]string{"error": "secret not found or already retrieved"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ciphertext": base64.RawURLEncoding.EncodeToString(secret.Ciphertext),
	})
}
