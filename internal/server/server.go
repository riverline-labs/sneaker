package server

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"sneaker/internal/store"
)

// Config holds server configuration.
type Config struct {
	Port  int
	Dev   bool
	WebFS fs.FS
}

// Server is the HTTP server for Sneaker.
type Server struct {
	config     Config
	httpServer *http.Server
	store      store.Store
}

// New creates a new Server with the given configuration.
// The store parameter may be nil (e.g., in tests that don't need a database).
func New(cfg Config, st store.Store) *Server {
	s := &Server{
		config: cfg,
		store:  st,
	}

	handler := s.routes()
	handler = requestLogger(handler)
	handler = securityHeaders(handler)

	// CSRF protection via Fetch Metadata: outermost middleware.
	cop := http.NewCrossOriginProtection()
	handler = cop.Handler(handler)

	s.httpServer = &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return s
}

// Handler returns the server's HTTP handler. Useful for testing.
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

// Start starts the HTTP server and blocks until the context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	if s.store != nil {
		s.startSessionCleanup(ctx)
		s.startSecretCleanup(ctx)
		s.startInviteCleanup(ctx)
	}

	s.warnNoTLS()

	slog.Info("starting sneaker server", "addr", s.httpServer.Addr)

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	slog.Info("shutting down server")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	slog.Info("server stopped")
	return nil
}

// Shutdown performs any additional cleanup beyond HTTP server shutdown.
// Note: store.Close() is called separately in cmd/serve.go after the
// HTTP server has fully stopped, ensuring in-flight requests complete.
func (s *Server) Shutdown() {
	slog.Info("server cleanup complete")
}

// startSessionCleanup runs a background goroutine that deletes expired sessions
// every 5 minutes. It stops when ctx is cancelled.
func (s *Server) startSessionCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				count, err := s.store.CleanExpiredSessions(ctx)
				if err != nil {
					slog.Error("session cleanup failed", "error", err)
					continue
				}
				if count > 0 {
					slog.Info("cleaned expired sessions", "count", count)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// startSecretCleanup runs a background goroutine that deletes expired secrets
// every 5 minutes. It stops when ctx is cancelled.
func (s *Server) startSecretCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				count, err := s.store.CleanExpiredSecrets(ctx)
				if err != nil {
					slog.Error("secret cleanup failed", "error", err)
					continue
				}
				if count > 0 {
					slog.Info("cleaned expired secrets", "count", count)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// startInviteCleanup runs a background goroutine that deletes expired invite
// tokens every 5 minutes. It stops when ctx is cancelled.
func (s *Server) startInviteCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				count, err := s.store.CleanExpiredInvites(ctx)
				if err != nil {
					slog.Error("invite cleanup failed", "error", err)
					continue
				}
				if count > 0 {
					slog.Info("cleaned expired invites", "count", count)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *Server) warnNoTLS() {
	warning := `
========================================================
  WARNING: Server is running without TLS.
  Do NOT use in production without a TLS-terminating
  reverse proxy (nginx, caddy, etc).
========================================================`
	fmt.Fprintln(os.Stderr, warning)
	slog.Warn("server running without TLS",
		"action_required", "deploy behind TLS-terminating reverse proxy",
	)
}
