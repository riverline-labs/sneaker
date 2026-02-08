package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var sendCmd = &cobra.Command{
	Use:   "send [secret]",
	Short: "Send a one-time secret and get a shareable link",
	Long: `Encrypt a secret and upload it.

Link mode (default): Returns a URL with the decryption key in the fragment.
Identity mode (--to): Encrypts to a recipient's registered public key.

Pass the secret as an argument or pipe it via stdin.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runSend,
}

func init() {
	sendCmd.Flags().String("to", "", "Recipient email or @team for group send")
	sendCmd.Flags().String("ttl", "", "Secret expiry duration (e.g. 30m, 1h, 12h, 1d, 7d)")
	sendCmd.Flags().Bool("passphrase", false, "Add passphrase protection to link-mode secret")
	rootCmd.AddCommand(sendCmd)
}

// parseTTL parses a human-friendly duration string into a time.Duration.
// Supports standard Go durations (30m, 1h, 12h) plus a custom "d" suffix for days.
func parseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("empty TTL")
	}
	// Custom "d" suffix for days (not supported by time.ParseDuration).
	if strings.HasSuffix(s, "d") {
		numStr := strings.TrimSuffix(s, "d")
		days, err := strconv.Atoi(numStr)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid TTL: %s", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid TTL %q (examples: 30m, 1h, 12h, 1d, 7d): %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("TTL must be positive")
	}
	return d, nil
}

// encryptLinkMode generates an ephemeral X25519 keypair, encrypts plaintext to
// the ephemeral recipient, and returns the ciphertext and the private key string
// (AGE-SECRET-KEY-...) for use as the URL fragment.
func encryptLinkMode(plaintext []byte) (ciphertext []byte, fragment string, err error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, "", fmt.Errorf("generating keypair: %w", err)
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, identity.Recipient())
	if err != nil {
		return nil, "", fmt.Errorf("creating encrypter: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, "", fmt.Errorf("writing plaintext: %w", err)
	}
	// Close finalizes encryption and writes the AEAD tag. Must check error.
	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("finalizing encryption: %w", err)
	}

	return buf.Bytes(), identity.String(), nil
}

// encryptLinkModeWithPassphrase wraps link-mode encryption with an additional
// scrypt passphrase layer. The plaintext is first encrypted with an ephemeral
// X25519 key (link mode), then the resulting ciphertext is encrypted again
// with the passphrase using age's scrypt recipient. The URL fragment (ephemeral
// private key) is still needed alongside the passphrase for full decryption.
func encryptLinkModeWithPassphrase(plaintext []byte, passphrase string) (ciphertext []byte, fragment string, err error) {
	x25519Ct, fragment, err := encryptLinkMode(plaintext)
	if err != nil {
		return nil, "", err
	}
	scryptRecipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, "", fmt.Errorf("creating scrypt recipient: %w", err)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, scryptRecipient)
	if err != nil {
		return nil, "", fmt.Errorf("creating passphrase encrypter: %w", err)
	}
	if _, err := w.Write(x25519Ct); err != nil {
		return nil, "", fmt.Errorf("writing to passphrase encrypter: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("finalizing passphrase encryption: %w", err)
	}
	return buf.Bytes(), fragment, nil
}

// postSecret sends the encrypted ciphertext to the server and returns the secret ID.
func postSecret(cfg *CLIConfig, ciphertext []byte, ttlSeconds int, passphraseProtected bool) (string, error) {
	reqBody := map[string]any{
		"ciphertext": base64.RawURLEncoding.EncodeToString(ciphertext),
	}
	if ttlSeconds > 0 {
		reqBody["ttl_seconds"] = ttlSeconds
	}
	if passphraseProtected {
		reqBody["passphrase_protected"] = true
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("encoding request: %w", err)
	}

	req, err := http.NewRequest("POST", cfg.Server+"/api/secrets", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return "", fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp["error"])
	}

	var result struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}
	return result.ID, nil
}

// encryptIdentityMode encrypts plaintext to a known recipient's AGE public key.
// Unlike link mode, no ephemeral key is generated -- the recipient uses their
// stored identity key to decrypt.
func encryptIdentityMode(plaintext []byte, recipientPubKey string) ([]byte, error) {
	recipient, err := age.ParseX25519Recipient(recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("parsing recipient public key: %w", err)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, fmt.Errorf("creating encrypter: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("writing plaintext: %w", err)
	}
	// Explicitly close (not defer) to check AEAD finalization error.
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finalizing encryption: %w", err)
	}
	return buf.Bytes(), nil
}

// fetchRecipientKey retrieves a recipient's AGE public key from the server.
func fetchRecipientKey(cfg *CLIConfig, email string) (string, error) {
	reqURL := cfg.Server + "/api/identity/pubkey/" + url.PathEscape(email)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("recipient %s not found or has no public key", email)
	}
	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return "", fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp["error"])
	}

	var result struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}
	return result.PublicKey, nil
}

// postIdentitySecret sends an identity-mode encrypted secret to the server.
func postIdentitySecret(cfg *CLIConfig, ciphertext []byte, recipientEmail string, ttlSeconds int) error {
	reqBody := map[string]any{
		"ciphertext":      base64.RawURLEncoding.EncodeToString(ciphertext),
		"mode":            "identity",
		"recipient_email": recipientEmail,
	}
	if ttlSeconds > 0 {
		reqBody["ttl_seconds"] = ttlSeconds
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("encoding request: %w", err)
	}

	req, err := http.NewRequest("POST", cfg.Server+"/api/secrets", bytes.NewReader(body))
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

	if resp.StatusCode != http.StatusCreated {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp["error"])
	}

	return nil
}

// teamMemberInfo represents a member returned by the team members API.
type teamMemberInfo struct {
	Email     string `json:"email"`
	PublicKey string `json:"public_key"`
	Role      string `json:"role"`
}

// fetchTeamMembers retrieves the members of a team from the server.
func fetchTeamMembers(cfg *CLIConfig, teamName string) ([]teamMemberInfo, error) {
	reqURL := cfg.Server + "/api/teams/" + url.PathEscape(teamName) + "/members"
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("not a member of team @%s", teamName)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("team @%s not found", teamName)
	}
	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp["error"])
	}

	var members []teamMemberInfo
	if err := json.NewDecoder(resp.Body).Decode(&members); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return members, nil
}

// groupSend encrypts and sends a secret to each member of a team individually.
// The sender is excluded from recipients, and members without public keys are skipped.
func groupSend(cmd *cobra.Command, cfg *CLIConfig, teamName string, plaintext []byte, ttlSeconds int) error {
	members, err := fetchTeamMembers(cfg, teamName)
	if err != nil {
		return err
	}

	senderEmail := cfg.Email // empty for configs saved before this feature

	var sent, skipped int
	for _, m := range members {
		if m.Email == senderEmail && senderEmail != "" {
			continue
		}
		if m.PublicKey == "" {
			fmt.Fprintf(os.Stderr, "warning: skipping %s (no public key)\n", m.Email)
			skipped++
			continue
		}
		ciphertext, err := encryptIdentityMode(plaintext, m.PublicKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", m.Email, err)
			skipped++
			continue
		}
		if err := postIdentitySecret(cfg, ciphertext, m.Email, ttlSeconds); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to send to %s: %v\n", m.Email, err)
			skipped++
			continue
		}
		sent++
	}

	if sent == 0 {
		return fmt.Errorf("no secrets sent (team @%s has no eligible recipients)", teamName)
	}

	total := sent + skipped
	if skipped > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "Secret sent to %d/%d team members (%d skipped)\n", sent, total, skipped)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Secret sent to %d team members\n", sent)
	}
	return nil
}

func runSend(cmd *cobra.Command, args []string) error {
	var plaintext []byte

	if len(args) > 0 {
		plaintext = []byte(args[0])
	} else {
		// Check if stdin has data (pipe mode).
		info, _ := os.Stdin.Stat()
		if info.Mode()&os.ModeCharDevice == 0 {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("reading stdin: %w", err)
			}
			plaintext = bytes.TrimRight(data, "\n")
		} else {
			return fmt.Errorf("provide a secret as argument or pipe via stdin")
		}
	}

	if len(plaintext) == 0 {
		return fmt.Errorf("secret cannot be empty")
	}
	if len(plaintext) > 1024*1024 {
		return fmt.Errorf("secret too large (max 1MB)")
	}

	// Load CLI config for server URL and token.
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("not logged in (run 'sneaker login' first): %w", err)
	}

	// Parse --ttl flag.
	ttlStr, _ := cmd.Flags().GetString("ttl")
	var ttlSeconds int
	if ttlStr != "" {
		d, err := parseTTL(ttlStr)
		if err != nil {
			return err
		}
		ttlSeconds = int(d.Seconds())
	}

	// Parse --passphrase flag.
	toRecipient, _ := cmd.Flags().GetString("to")
	usePassphrase, _ := cmd.Flags().GetBool("passphrase")
	if usePassphrase && toRecipient != "" {
		return fmt.Errorf("--passphrase is only available for link-mode secrets (not with --to)")
	}

	// Prompt for passphrase if requested.
	var passphrase string
	if usePassphrase {
		fmt.Fprint(os.Stderr, "Enter passphrase: ")
		passphraseBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("reading passphrase: %w", err)
		}
		fmt.Fprintln(os.Stderr)
		passphrase = string(passphraseBytes)
		if passphrase == "" {
			return fmt.Errorf("passphrase cannot be empty")
		}
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		confirmBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("reading passphrase confirmation: %w", err)
		}
		fmt.Fprintln(os.Stderr)
		if string(confirmBytes) != passphrase {
			return fmt.Errorf("passphrases do not match")
		}
	}

	// Branch on mode: group (@team), identity (--to email), or link (default).
	if toRecipient != "" {
		if strings.HasPrefix(toRecipient, "@") {
			teamName := toRecipient[1:]
			if teamName == "" {
				return fmt.Errorf("provide a team name after @")
			}
			return groupSend(cmd, cfg, teamName, plaintext, ttlSeconds)
		}
		// Identity mode: encrypt to recipient's registered public key.
		pubKey, err := fetchRecipientKey(cfg, toRecipient)
		if err != nil {
			return err
		}
		ciphertext, err := encryptIdentityMode(plaintext, pubKey)
		if err != nil {
			return err
		}
		if err := postIdentitySecret(cfg, ciphertext, toRecipient, ttlSeconds); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Secret sent to %s\n", toRecipient)
		return nil
	}

	// Link mode: encrypt with ephemeral X25519 keypair.
	var ciphertext []byte
	var fragment string
	if passphrase != "" {
		ciphertext, fragment, err = encryptLinkModeWithPassphrase(plaintext, passphrase)
	} else {
		ciphertext, fragment, err = encryptLinkMode(plaintext)
	}
	if err != nil {
		return err
	}

	// POST ciphertext to server.
	secretID, err := postSecret(cfg, ciphertext, ttlSeconds, passphrase != "")
	if err != nil {
		return err
	}

	// Print shareable URL with private key in fragment.
	shareURL := fmt.Sprintf("%s/s/%s#%s", cfg.Server, secretID, fragment)
	fmt.Fprintln(cmd.OutOrStdout(), shareURL)

	if passphrase != "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Note: Recipient will need the passphrase to decrypt.")
	}
	return nil
}
