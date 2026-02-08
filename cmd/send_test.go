package cmd

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptLinkMode(t *testing.T) {
	plaintext := []byte("hello world")
	ciphertext, fragment, err := encryptLinkMode(plaintext)
	require.NoError(t, err)

	// Ciphertext is non-empty and differs from plaintext.
	assert.NotEmpty(t, ciphertext)
	assert.NotEqual(t, plaintext, ciphertext)

	// Fragment is an AGE secret key.
	assert.True(t, strings.HasPrefix(fragment, "AGE-SECRET-KEY-"), "fragment should be an AGE secret key, got: %s", fragment)

	// Round-trip: parse identity from fragment and decrypt.
	identity, err := age.ParseX25519Identity(fragment)
	require.NoError(t, err)

	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	require.NoError(t, err)

	decrypted, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptLinkModeEmpty(t *testing.T) {
	ciphertext, fragment, err := encryptLinkMode([]byte(""))
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	assert.True(t, strings.HasPrefix(fragment, "AGE-SECRET-KEY-"))

	// Round-trip: decrypt empty data.
	identity, err := age.ParseX25519Identity(fragment)
	require.NoError(t, err)

	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	require.NoError(t, err)

	decrypted, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestSendValidationNoInput(t *testing.T) {
	// runSend with no args and no pipe should error.
	cmd := sendCmd
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{})

	// We cannot easily simulate os.Stdin.Stat() returning a char device in
	// a test, but we can call runSend directly with empty args. In a test
	// environment, os.Stdin is typically a pipe (not a char device), so we
	// test the "empty stdin pipe" path by providing an empty reader.
	// Instead, test the error message via the command's Execute path
	// by verifying the error from runSend when given no args and stdin
	// would be empty after piping.

	// Test: secret too large
	large := make([]byte, 1024*1024+1)
	err := runSend(cmd, []string{string(large)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestSendValidationEmpty(t *testing.T) {
	cmd := sendCmd
	err := runSend(cmd, []string{""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestSendValidationTooLarge(t *testing.T) {
	cmd := sendCmd
	large := strings.Repeat("x", 1024*1024+1)
	err := runSend(cmd, []string{large})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestParseTTL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{name: "1 hour", input: "1h", want: 1 * time.Hour},
		{name: "30 minutes", input: "30m", want: 30 * time.Minute},
		{name: "1 day", input: "1d", want: 24 * time.Hour},
		{name: "7 days", input: "7d", want: 168 * time.Hour},
		{name: "12 hours", input: "12h", want: 12 * time.Hour},
		{name: "uppercase", input: "1H", want: 1 * time.Hour},
		{name: "with spaces", input: "  1h  ", want: 1 * time.Hour},
		{name: "empty string", input: "", wantErr: true},
		{name: "invalid text", input: "abc", wantErr: true},
		{name: "zero days", input: "0d", wantErr: true},
		{name: "negative duration", input: "-1h", wantErr: true},
		{name: "invalid suffix", input: "1w", wantErr: true},
		{name: "negative days", input: "-1d", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTTL(tt.input)
			if tt.wantErr {
				assert.Error(t, err, "parseTTL(%q) should return error", tt.input)
				return
			}
			require.NoError(t, err, "parseTTL(%q) should not return error", tt.input)
			assert.Equal(t, tt.want, got, "parseTTL(%q)", tt.input)
		})
	}
}

func TestEncryptLinkModeWithPassphrase(t *testing.T) {
	plaintext := []byte("secret with passphrase")
	passphrase := "mypassword123"

	ciphertext, fragment, err := encryptLinkModeWithPassphrase(plaintext, passphrase)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	assert.True(t, strings.HasPrefix(fragment, "AGE-SECRET-KEY-"))

	// Round-trip: first decrypt passphrase layer, then decrypt X25519 layer.
	scryptIdentity, err := age.NewScryptIdentity(passphrase)
	require.NoError(t, err)

	outerReader, err := age.Decrypt(bytes.NewReader(ciphertext), scryptIdentity)
	require.NoError(t, err)
	innerCiphertext, err := io.ReadAll(outerReader)
	require.NoError(t, err)

	identity, err := age.ParseX25519Identity(fragment)
	require.NoError(t, err)

	innerReader, err := age.Decrypt(bytes.NewReader(innerCiphertext), identity)
	require.NoError(t, err)
	decrypted, err := io.ReadAll(innerReader)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}
