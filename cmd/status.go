package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status <secret-id>",
	Short: "Check the status of a sent secret",
	Long:  "Check whether a secret you sent is still pending, has been retrieved, or has expired.",
	Args:  cobra.ExactArgs(1),
	RunE:  runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("not logged in (run 'sneaker login' first): %w", err)
	}

	id := args[0]

	req, err := http.NewRequest("GET", cfg.Server+"/api/secrets/"+id+"/status", nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("not logged in (run 'sneaker login' first)")
	case http.StatusNotFound:
		fmt.Fprintln(cmd.OutOrStdout(), "Secret not found (may have been cleaned up, or you are not the sender)")
		return nil
	case http.StatusOK:
		// continue below
	default:
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp["error"])
	}

	var result struct {
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	// Parse timestamps and format in local time.
	createdAt, _ := time.Parse("2006-01-02T15:04:05Z", result.CreatedAt)
	expiresAt, _ := time.Parse("2006-01-02T15:04:05Z", result.ExpiresAt)

	fmt.Fprintf(cmd.OutOrStdout(), "Secret:  %s\n", id)
	fmt.Fprintf(cmd.OutOrStdout(), "Status:  %s\n", result.Status)
	if !createdAt.IsZero() {
		fmt.Fprintf(cmd.OutOrStdout(), "Created: %s\n", createdAt.Local().Format("2006-01-02 15:04:05 MST"))
	}
	if !expiresAt.IsZero() {
		fmt.Fprintf(cmd.OutOrStdout(), "Expires: %s\n", expiresAt.Local().Format("2006-01-02 15:04:05 MST"))
	}

	return nil
}
