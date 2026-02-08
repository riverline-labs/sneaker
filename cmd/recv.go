package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"filippo.io/age"
	"github.com/spf13/cobra"
)

var recvCmd = &cobra.Command{
	Use:   "recv",
	Short: "Receive and decrypt pending identity-mode secrets",
	Long:  "Fetch all pending secrets from your inbox, decrypt them with your local\nidentity key, and display the plaintext. Each secret is consumed (deleted\nfrom the server) after successful retrieval.",
	RunE:  runRecv,
}

func init() {
	rootCmd.AddCommand(recvCmd)
}

// inboxSecret represents a pending secret in the user's inbox.
type inboxSecret struct {
	ID          string `json:"id"`
	SenderEmail string `json:"sender_email"`
	CreatedAt   string `json:"created_at"`
}

// loadIdentity reads the AGE X25519 identity from the local key file.
func loadIdentity() (*age.X25519Identity, error) {
	keyPath, err := identityKeyPath()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no identity found (run 'sneaker init' first)")
		}
		return nil, fmt.Errorf("opening identity file: %w", err)
	}
	defer f.Close()

	identities, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parsing identity file: %w", err)
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("identity file is empty (run 'sneaker init' to regenerate)")
	}

	id, ok := identities[0].(*age.X25519Identity)
	if !ok {
		return nil, fmt.Errorf("unexpected identity type in %s (expected X25519)", keyPath)
	}

	return id, nil
}

// fetchInbox retrieves the list of pending secrets from the server.
func fetchInbox(cfg *CLIConfig) ([]inboxSecret, error) {
	req, err := http.NewRequest("GET", cfg.Server+"/api/secrets/inbox", nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp["error"])
	}

	var secrets []inboxSecret
	if err := json.NewDecoder(resp.Body).Decode(&secrets); err != nil {
		return nil, fmt.Errorf("decoding inbox: %w", err)
	}

	return secrets, nil
}

// consumeInboxSecret retrieves and deletes a single secret from the inbox,
// returning the raw ciphertext bytes.
func consumeInboxSecret(cfg *CLIConfig, id string) ([]byte, error) {
	req, err := http.NewRequest("DELETE", cfg.Server+"/api/secrets/inbox/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusGone {
		return nil, fmt.Errorf("secret already consumed or expired")
	}
	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp["error"])
	}

	var result struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(result.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}

	return ciphertext, nil
}

func runRecv(cmd *cobra.Command, args []string) error {
	// Load CLI config for server URL and token.
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("not logged in (run 'sneaker login' first): %w", err)
	}

	// Load local AGE identity for decryption.
	identity, err := loadIdentity()
	if err != nil {
		return err
	}

	// Fetch pending secrets from inbox.
	secrets, err := fetchInbox(cfg)
	if err != nil {
		return err
	}

	if len(secrets) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No pending secrets.")
		return nil
	}

	stderr := cmd.ErrOrStderr()
	stdout := cmd.OutOrStdout()

	for _, secret := range secrets {
		// Consume (retrieve and delete) the secret from the server.
		ciphertext, err := consumeInboxSecret(cfg, secret.ID)
		if err != nil {
			fmt.Fprintf(stderr, "warning: secret %s: %v\n", secret.ID, err)
			continue
		}

		// Decrypt with local identity.
		reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
		if err != nil {
			fmt.Fprintf(stderr, "warning: secret %s: decrypt failed: %v\n", secret.ID, err)
			continue
		}

		plaintext, err := io.ReadAll(reader)
		if err != nil {
			fmt.Fprintf(stderr, "warning: secret %s: reading plaintext: %v\n", secret.ID, err)
			continue
		}

		fmt.Fprintf(stdout, "--- From: %s (%s) ---\n%s\n", secret.SenderEmail, secret.CreatedAt, plaintext)
	}

	return nil
}
