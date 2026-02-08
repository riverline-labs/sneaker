package server

import (
	"io/fs"
	"log/slog"
	"net/http"
	"os"
)

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("GET /api/health", s.handleHealth)

	// Auth routes (public -- no requireAuth wrapper)
	mux.HandleFunc("POST /api/auth/signup", s.handleSignup)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	mux.Handle("GET /api/auth/me", s.requireAuth(http.HandlerFunc(s.handleMe)))

	// Identity routes (must be before /api/secrets/{id} so /api/secrets/inbox matches first)
	mux.Handle("PUT /api/identity/pubkey", s.requireAuth(http.HandlerFunc(s.handleSetPublicKey)))
	mux.Handle("GET /api/identity/pubkey/{email}", s.requireAuth(http.HandlerFunc(s.handleGetPublicKey)))
	mux.Handle("GET /api/secrets/inbox", s.requireAuth(http.HandlerFunc(s.handleListInbox)))
	mux.Handle("DELETE /api/secrets/inbox/{id}", s.requireAuth(http.HandlerFunc(s.handleConsumeInboxSecret)))

	// Team routes
	mux.Handle("POST /api/teams/join", s.requireAuth(http.HandlerFunc(s.handleJoinTeam)))
	mux.Handle("POST /api/teams", s.requireAuth(http.HandlerFunc(s.handleCreateTeam)))
	mux.Handle("GET /api/teams", s.requireAuth(http.HandlerFunc(s.handleListTeams)))
	mux.Handle("GET /api/teams/{name}/members", s.requireAuth(http.HandlerFunc(s.handleListTeamMembers)))
	mux.Handle("POST /api/teams/{name}/invites", s.requireAuth(http.HandlerFunc(s.handleCreateInvite)))

	// Secret routes
	mux.Handle("POST /api/secrets", s.requireAuth(http.HandlerFunc(s.handleCreateSecret)))
	mux.Handle("GET /api/secrets/{id}/status", s.requireAuth(http.HandlerFunc(s.handleGetSecretStatus)))
	mux.HandleFunc("GET /api/secrets/{id}", s.handleGetSecret)

	// Reveal page route (must be before the catch-all file server)
	mux.HandleFunc("GET /s/{id}", s.handleRevealPage)

	// Frontend static file serving
	if s.config.Dev {
		slog.Warn("dev mode active: serving frontend from disk")
		mux.Handle("GET /", http.FileServer(http.Dir("web")))
	} else {
		frontendFS, err := fs.Sub(s.config.WebFS, "web")
		if err != nil {
			slog.Error("failed to create sub filesystem for web assets", "error", err)
			os.Exit(1)
		}
		mux.Handle("GET /", http.FileServerFS(frontendFS))
	}

	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if s.store != nil {
		if err := s.store.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"degraded","db":"error"}`))
			return
		}
	}

	w.Write([]byte(`{"status":"ok","db":"connected"}`))
}

// handleRevealPage serves the reveal.html page for any /s/{id} path.
// The {id} is consumed by client-side JavaScript, not the server.
func (s *Server) handleRevealPage(w http.ResponseWriter, r *http.Request) {
	if s.config.Dev {
		http.ServeFile(w, r, "web/reveal.html")
		return
	}
	frontendFS, err := fs.Sub(s.config.WebFS, "web")
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.ServeFileFS(w, r, frontendFS, "reveal.html")
}
