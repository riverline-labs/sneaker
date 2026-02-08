package cmd

import (
	"embed"
	"fmt"
	"log/slog"
	"os/signal"
	"syscall"

	"sneaker/internal/server"
	"sneaker/internal/store"

	"github.com/spf13/cobra"
)

var (
	flagPort int
	flagDev  bool
	flagDB   string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Sneaker HTTP server",
	RunE:  runServe,
}

func init() {
	serveCmd.Flags().IntVar(&flagPort, "port", 7657, "Port to listen on")
	serveCmd.Flags().BoolVar(&flagDev, "dev", false, "Serve frontend from disk (live reload)")
	serveCmd.Flags().StringVar(&flagDB, "db", "sneaker.db", "Path to SQLite database file")
	rootCmd.AddCommand(serveCmd)
}

// WebFS is set by main before Execute() to provide the embedded web assets.
var WebFS embed.FS

func runServe(cmd *cobra.Command, args []string) error {
	// Initialize database store.
	st, err := store.NewSQLiteStore(flagDB)
	if err != nil {
		return fmt.Errorf("database init: %w", err)
	}

	cfg := server.Config{
		Port:  flagPort,
		Dev:   flagDev,
		WebFS: WebFS,
	}

	srv := server.New(cfg, st)

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	// Close database after server has fully stopped.
	if err := st.Close(); err != nil {
		slog.Error("error closing database", "error", err)
	} else {
		slog.Info("database closed")
	}

	return nil
}
