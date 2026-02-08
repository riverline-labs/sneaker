package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"sneaker/internal/store"
)

// contextKey is an unexported type for context keys in this package.
type contextKey int

const (
	userContextKey contextKey = iota
)

// securityHeaders sets security headers on every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// requestLogger logs method, path, status code, and duration for each request.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration", time.Since(start),
		)
	})
}

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
	}
	return w.ResponseWriter.Write(b)
}

// requireAuth is middleware that validates a session token (cookie or Bearer header)
// and injects the authenticated *store.User into the request context.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawToken, _ := extractToken(r)
		if rawToken == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}

		tokenHash := hashToken(rawToken)
		user, err := s.store.GetUserBySession(r.Context(), tokenHash)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid session"})
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UserFromContext extracts the authenticated user from the request context.
// Returns nil if no user is present (request did not pass through requireAuth).
func UserFromContext(ctx context.Context) *store.User {
	u, _ := ctx.Value(userContextKey).(*store.User)
	return u
}
