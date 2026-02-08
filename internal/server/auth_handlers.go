package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"sneaker/internal/auth"
)

// hashToken computes a SHA-256 hash of the raw token and returns it hex-encoded.
// Session tokens are always hashed before storage or lookup.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// handleSignup creates a new user account and returns a session.
func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Validate email.
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if _, err := mail.ParseAddress(email); err != nil || email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid email address"})
		return
	}

	// Validate password.
	if len(req.Password) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
		return
	}

	// Hash password.
	passwordHash, err := auth.HashPassword(req.Password, auth.DefaultParams)
	if err != nil {
		slog.Error("failed to hash password", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	// Create user.
	user, err := s.store.CreateUser(r.Context(), email, passwordHash)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "email already registered"})
			return
		}
		slog.Error("failed to create user", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	// Create session.
	rawToken := rand.Text()
	tokenHash := hashToken(rawToken)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	if err := s.store.CreateSession(r.Context(), user.ID, tokenHash, expiresAt); err != nil {
		slog.Error("failed to create session", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	// Respond based on Accept header.
	userPayload := map[string]any{
		"id":    user.ID,
		"email": user.Email,
	}

	if wantsCLI(r) {
		writeJSON(w, http.StatusCreated, map[string]any{
			"token": rawToken,
			"user":  userPayload,
		})
		return
	}

	// Web client: set cookie.
	setSessionCookie(w, rawToken, s.config.Dev)
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":   true,
		"user": userPayload,
	})
}

// handleLogin authenticates a user and returns a session.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	// Fetch user -- timing-safe: always run VerifyPassword.
	user, err := s.store.GetUserByEmail(r.Context(), email)

	passwordHash := auth.DummyHash
	if err == nil && user != nil {
		passwordHash = user.PasswordHash
	}

	match, verifyErr := auth.VerifyPassword(req.Password, passwordHash)
	if verifyErr != nil {
		slog.Error("password verification error", "error", verifyErr)
	}

	if !match || user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid email or password"})
		return
	}

	// Create session.
	rawToken := rand.Text()
	tokenHash := hashToken(rawToken)
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	if err := s.store.CreateSession(r.Context(), user.ID, tokenHash, expiresAt); err != nil {
		slog.Error("failed to create session", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	// Respond based on Accept header.
	userPayload := map[string]any{
		"id":    user.ID,
		"email": user.Email,
	}

	if wantsCLI(r) {
		writeJSON(w, http.StatusOK, map[string]any{
			"token": rawToken,
			"user":  userPayload,
		})
		return
	}

	setSessionCookie(w, rawToken, s.config.Dev)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":   true,
		"user": userPayload,
	})
}

// handleLogout invalidates the current session.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	rawToken, fromCookie := extractToken(r)
	if rawToken == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	tokenHash := hashToken(rawToken)
	if err := s.store.DeleteSession(r.Context(), tokenHash); err != nil {
		slog.Error("failed to delete session", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	// Clear cookie if that's how the session was provided.
	if fromCookie {
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleMe returns the authenticated user's email.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"email": user.Email})
}

// --- helpers ---

// writeJSON encodes v as JSON and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to write JSON response", "error", err)
	}
}

// wantsCLI returns true if the client prefers a JSON token response (CLI mode).
// CLI clients send Accept: application/json; browsers send text/html or */*.
func wantsCLI(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json")
}

// setSessionCookie sets an HttpOnly session cookie with the raw token.
func setSessionCookie(w http.ResponseWriter, rawToken string, devMode bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    rawToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   !devMode,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   30 * 24 * 60 * 60, // 30 days
	})
}

// extractToken retrieves the raw session token from the request.
// It checks the session cookie first, then falls back to the Authorization header.
// Returns the token and whether it came from a cookie.
func extractToken(r *http.Request) (token string, fromCookie bool) {
	if c, err := r.Cookie("session"); err == nil && c.Value != "" {
		return c.Value, true
	}
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer "), false
	}
	return "", false
}
