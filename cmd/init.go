package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate an AGE identity keypair",
	Long:  "Generate an AGE X25519 identity keypair and store it locally.\nThe public key is uploaded to the server so others can send you secrets.",
	RunE:  runInit,
}

func init() {
	initCmd.Flags().Bool("force", false, "Overwrite existing identity (WARNING: old secrets will be unrecoverable)")
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	keyPath, err := identityKeyPath()
	if err != nil {
		return err
	}

	force, _ := cmd.Flags().GetBool("force")

	// Check if identity already exists.
	if _, err := os.Stat(keyPath); err == nil && !force {
		return fmt.Errorf("identity already exists at %s\nUse --force to overwrite (WARNING: old secrets will be unrecoverable)", keyPath)
	}

	// Generate X25519 identity.
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generating keypair: %w", err)
	}

	// Ensure config directory exists.
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	// Write identity file in age-keygen format.
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&buf, "# public key: %s\n", identity.Recipient().String())
	fmt.Fprintln(&buf, identity.String())

	if err := os.WriteFile(keyPath, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("writing identity file: %w", err)
	}

	// User must be logged in to upload public key.
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("not logged in (run 'sneaker login' first): %w", err)
	}

	// Upload public key to server.
	if err := uploadPublicKey(cfg, identity.Recipient().String()); err != nil {
		return fmt.Errorf("uploading public key: %w", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Identity created!")
	fmt.Fprintf(cmd.OutOrStdout(), "Public key:  %s\n", identity.Recipient().String())
	fmt.Fprintf(cmd.OutOrStdout(), "Private key: %s\n", keyPath)
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintf(cmd.OutOrStdout(), "WARNING: Back up %s now.\n", keyPath)
	fmt.Fprintln(cmd.OutOrStdout(), "If you lose this file, you will not be able to decrypt secrets sent to you.")
	fmt.Fprintln(cmd.OutOrStdout(), "Public key uploaded to server.")
	return nil
}

// uploadPublicKey sends the user's AGE public key to the server.
func uploadPublicKey(cfg *CLIConfig, pubKey string) error {
	body, err := json.Marshal(map[string]string{
		"public_key": pubKey,
	})
	if err != nil {
		return fmt.Errorf("encoding request: %w", err)
	}

	req, err := http.NewRequest("PUT", cfg.Server+"/api/identity/pubkey", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp["error"])
	}

	return nil
}
