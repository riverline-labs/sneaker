package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

var teamInviteCmd = &cobra.Command{
	Use:   "invite <team>",
	Short: "Generate an invite token for a team",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamInvite,
}

func init() {
	teamCmd.AddCommand(teamInviteCmd)
}

func runTeamInvite(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("not logged in (run 'sneaker login' first): %w", err)
	}

	name := strings.ToLower(strings.TrimSpace(args[0]))

	reqURL := cfg.Server + "/api/teams/" + url.PathEscape(name) + "/invites"
	req, err := http.NewRequest("POST", reqURL, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("connecting to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("only the team owner can create invites")
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("team %q not found", name)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("not logged in (run 'sneaker login' first)")
	}
	if resp.StatusCode != http.StatusCreated {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp["error"])
	}

	var result struct {
		Token     string `json:"token"`
		Team      string `json:"team"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Invite token for team %q:\n\n", result.Team)
	fmt.Fprintf(out, "  %s\n\n", result.Token)
	fmt.Fprintln(out, "Share this token with the person you want to invite.")
	fmt.Fprintf(out, "Token expires: %s\n", result.ExpiresAt)
	return nil
}
