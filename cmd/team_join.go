package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

var teamJoinCmd = &cobra.Command{
	Use:   "join <token>",
	Short: "Join a team with an invite token",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamJoin,
}

func init() {
	teamCmd.AddCommand(teamJoinCmd)
}

func runTeamJoin(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("not logged in (run 'sneaker login' first): %w", err)
	}

	token := strings.TrimSpace(args[0])
	if token == "" {
		return fmt.Errorf("invite token cannot be empty")
	}

	body, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		return fmt.Errorf("encoding request: %w", err)
	}

	req, err := http.NewRequest("POST", cfg.Server+"/api/teams/join", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("connecting to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("invite token invalid or expired")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("not logged in (run 'sneaker login' first)")
	}
	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp["error"])
	}

	var result struct {
		Team string `json:"team"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Joined team %q!\n", result.Team)
	return nil
}
