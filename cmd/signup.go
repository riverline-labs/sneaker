package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var signupCmd = &cobra.Command{
	Use:   "signup",
	Short: "Create a new account on a Sneaker server",
	RunE:  runSignup,
}

func init() {
	signupCmd.Flags().String("server", "", "Server URL (e.g., https://sneaker.example.com)")
	rootCmd.AddCommand(signupCmd)
}

func runSignup(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	if server == "" {
		server = os.Getenv("SNEAKER_SERVER")
	}
	if server == "" {
		return fmt.Errorf("provide --server URL or set SNEAKER_SERVER")
	}
	server = strings.TrimRight(server, "/")

	// Prompt for credentials.
	var email, password string
	fmt.Fprint(cmd.OutOrStdout(), "Email: ")
	if _, err := fmt.Fscanln(cmd.InOrStdin(), &email); err != nil {
		return fmt.Errorf("reading email: %w", err)
	}
	fmt.Fprint(cmd.OutOrStdout(), "Password: ")
	if _, err := fmt.Fscanln(cmd.InOrStdin(), &password); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}

	// POST to /api/auth/signup.
	body, err := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	if err != nil {
		return fmt.Errorf("encoding request: %w", err)
	}

	req, err := http.NewRequest("POST", server+"/api/auth/signup", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("connecting to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("signup failed (%d): %s", resp.StatusCode, errResp["error"])
	}

	var result struct {
		Token string `json:"token"`
		User  struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	if err := saveConfig(&CLIConfig{
		Server: server,
		Token:  result.Token,
		Email:  result.User.Email,
	}); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Account created. Logged in as %s\n", result.User.Email)
	return nil
}
