package cmd

import (
	"crypto/rand"
	"fmt"
	"strings"

	"sneaker/internal/auth"
	"sneaker/internal/store"

	"github.com/spf13/cobra"
)

var adminResetPasswordCmd = &cobra.Command{
	Use:   "reset-password <email>",
	Short: "Reset a user's password",
	Long:  "Generate a new random password for the specified user, update the database, and invalidate all existing sessions. Opens the database directly -- no running server needed.",
	Args:  cobra.ExactArgs(1),
	RunE:  runAdminResetPassword,
}

func init() {
	adminResetPasswordCmd.Flags().StringVar(&flagDB, "db", "sneaker.db", "Path to SQLite database file")
	adminCmd.AddCommand(adminResetPasswordCmd)
}

func runAdminResetPassword(cmd *cobra.Command, args []string) error {
	email := strings.ToLower(strings.TrimSpace(args[0]))

	// Read --db flag from the command (not package-level var) for testability.
	dbPath, _ := cmd.Flags().GetString("db")
	if dbPath == "" {
		dbPath = "sneaker.db"
	}

	// Open database directly -- no server needed.
	st, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer st.Close()

	// Generate a random password (16 chars from crypto/rand.Text).
	newPassword := rand.Text()[:16]

	// Hash with Argon2id.
	hash, err := auth.HashPassword(newPassword, auth.DefaultParams)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	// Update the user's password.
	if err := st.UpdateUserPassword(cmd.Context(), email, hash); err != nil {
		return fmt.Errorf("updating password: %w", err)
	}

	// Invalidate all existing sessions for the user.
	if err := st.DeleteUserSessions(cmd.Context(), email); err != nil {
		return fmt.Errorf("deleting sessions: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Password reset for %s\nNew password: %s\n", email, newPassword)
	return nil
}
