package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var teamMembersCmd = &cobra.Command{
	Use:   "members <team>",
	Short: "List team members and their public keys",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamMembers,
}

func init() {
	teamCmd.AddCommand(teamMembersCmd)
}

func runTeamMembers(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("not logged in (run 'sneaker login' first): %w", err)
	}

	name := strings.ToLower(strings.TrimSpace(args[0]))

	reqURL := cfg.Server + "/api/teams/" + url.PathEscape(name) + "/members"
	req, err := http.NewRequest("GET", reqURL, nil)
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
		return fmt.Errorf("not a team member")
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("team %q not found", name)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("not logged in (run 'sneaker login' first)")
	}
	if resp.StatusCode != http.StatusOK {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp["error"])
	}

	var members []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&members); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Team: %s\n\n", name)

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "EMAIL\tROLE\tKEY")
	for _, m := range members {
		email, _ := m["email"].(string)
		role, _ := m["role"].(string)
		pubKey, _ := m["public_key"].(string)

		keyDisplay := "(no key)"
		if pubKey != "" {
			keyDisplay = abbreviateKey(pubKey)
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\n", email, role, keyDisplay)
	}
	tw.Flush()

	return nil
}

// abbreviateKey shows the first 10 and last 3 chars of a public key with "..." between.
func abbreviateKey(key string) string {
	if len(key) <= 16 {
		return key
	}
	return key[:10] + "..." + key[len(key)-3:]
}
