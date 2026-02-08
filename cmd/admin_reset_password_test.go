package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sneaker/internal/auth"
	"sneaker/internal/store"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newAdminResetCmd returns a fresh command wired to the admin parent to avoid
// shared state between tests.
func newAdminResetCmd() *cobra.Command {
	root := &cobra.Command{Use: "sneaker"}
	admin := &cobra.Command{Use: "admin"}
	reset := &cobra.Command{
		Use:  "reset-password <email>",
		Args: cobra.ExactArgs(1),
		RunE: runAdminResetPassword,
	}
	var dbFlag string
	reset.Flags().StringVar(&dbFlag, "db", "sneaker.db", "Path to SQLite database file")
	admin.AddCommand(reset)
	root.AddCommand(admin)
	return root
}

func TestAdminResetPassword(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// Create store and seed a user.
	st, err := store.NewSQLiteStore(dbPath)
	require.NoError(t, err)
	defer st.Close()

	origHash, err := auth.HashPassword("original-password", auth.DefaultParams)
	require.NoError(t, err)

	user, err := st.CreateUser(context.Background(), "test@example.com", origHash)
	require.NoError(t, err)

	// Create a session so we can verify it gets deleted.
	err = st.CreateSession(context.Background(), user.ID, "session-hash-1", time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	// Verify session exists.
	_, err = st.GetUserBySession(context.Background(), "session-hash-1")
	require.NoError(t, err)

	// Close the store before running the command (command opens its own).
	st.Close()

	// Run the admin reset-password command.
	root := newAdminResetCmd()
	root.SetArgs([]string{"admin", "reset-password", "--db", dbPath, "test@example.com"})
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	err = root.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Password reset for test@example.com")
	assert.Contains(t, output, "New password:")

	// Extract the new password from output.
	lines := strings.Split(strings.TrimSpace(output), "\n")
	require.Len(t, lines, 2)
	newPassword := strings.TrimPrefix(lines[1], "New password: ")
	assert.Len(t, newPassword, 16)

	// Reopen store to verify changes.
	st2, err := store.NewSQLiteStore(dbPath)
	require.NoError(t, err)
	defer st2.Close()

	// Verify the new password works against the updated hash.
	updatedUser, err := st2.GetUserByEmail(context.Background(), "test@example.com")
	require.NoError(t, err)
	match, err := auth.VerifyPassword(newPassword, updatedUser.PasswordHash)
	require.NoError(t, err)
	assert.True(t, match, "new password should verify against updated hash")

	// Verify old password no longer works.
	match, err = auth.VerifyPassword("original-password", updatedUser.PasswordHash)
	require.NoError(t, err)
	assert.False(t, match, "old password should not verify")

	// Verify sessions were deleted.
	_, err = st2.GetUserBySession(context.Background(), "session-hash-1")
	assert.Error(t, err, "session should be deleted after password reset")
}

func TestAdminResetPasswordUserNotFound(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// Create store to initialize schema, then close.
	st, err := store.NewSQLiteStore(dbPath)
	require.NoError(t, err)
	st.Close()

	// Run the admin reset-password command for a nonexistent user.
	root := newAdminResetCmd()
	root.SetArgs([]string{"admin", "reset-password", "--db", dbPath, "nobody@example.com"})
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	err = root.Execute()
	assert.Error(t, err, "should error for nonexistent user")
	assert.Contains(t, err.Error(), "user not found")
}
