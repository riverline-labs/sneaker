package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

var teamCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new team",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamCreate,
}

func init() {
	teamCmd.AddCommand(teamCreateCmd)
}

func runTeamCreate(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("not logged in (run 'sneaker login' first): %w", err)
	}

	name := strings.ToLower(strings.TrimSpace(args[0]))
	if name == "" {
		return fmt.Errorf("team name cannot be empty")
	}

	body, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		return fmt.Errorf("encoding request: %w", err)
	}

	req, err := http.NewRequest("POST", cfg.Server+"/api/teams", bytes.NewReader(body))
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

	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("team name %q is already taken", name)
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
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Team %q created. You are the owner.\n", result.Name)
	return nil
}
