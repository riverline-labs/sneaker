package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sneaker/internal/server"
	"sneaker/internal/store"

	"github.com/spf13/cobra"
)

var provisionCmd = &cobra.Command{
	Use:   "provision",
	Short: "Bootstrap a fresh Sneaker instance (server + admin account + team)",
	RunE:  runProvision,
}

func init() {
	provisionCmd.Flags().IntVar(&flagPort, "port", 7657, "Port to listen on")
	provisionCmd.Flags().BoolVar(&flagDev, "dev", false, "Serve frontend from disk (live reload)")
	provisionCmd.Flags().StringVar(&flagDB, "db", "sneaker.db", "Path to SQLite database file")
	provisionCmd.Flags().String("email", "", "Admin email address")
	provisionCmd.Flags().String("password", "", "Admin password")
	provisionCmd.Flags().String("team", "", "Team name to create")
	rootCmd.AddCommand(provisionCmd)
}

func runProvision(cmd *cobra.Command, args []string) error {
	email, _ := cmd.Flags().GetString("email")
	password, _ := cmd.Flags().GetString("password")
	teamName, _ := cmd.Flags().GetString("team")

	// Prompt for missing inputs.
	if email == "" {
		fmt.Fprint(cmd.OutOrStdout(), "Admin email: ")
		if _, err := fmt.Fscanln(cmd.InOrStdin(), &email); err != nil {
			return fmt.Errorf("reading email: %w", err)
		}
	}
	if password == "" {
		fmt.Fprint(cmd.OutOrStdout(), "Admin password: ")
		if _, err := fmt.Fscanln(cmd.InOrStdin(), &password); err != nil {
			return fmt.Errorf("reading password: %w", err)
		}
	}
	if teamName == "" {
		fmt.Fprint(cmd.OutOrStdout(), "Team name: ")
		if _, err := fmt.Fscanln(cmd.InOrStdin(), &teamName); err != nil {
			return fmt.Errorf("reading team name: %w", err)
		}
	}
	teamName = strings.ToLower(strings.TrimSpace(teamName))

	// Initialize database store.
	st, err := store.NewSQLiteStore(flagDB)
	if err != nil {
		return fmt.Errorf("database init: %w", err)
	}

	cfg := server.Config{
		Port:  flagPort,
		Dev:   flagDev,
		WebFS: WebFS,
	}

	srv := server.New(cfg, st)

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start server in a goroutine.
	serverErr := make(chan error, 1)
	go func() {
		if err := srv.Start(ctx); err != nil {
			serverErr <- err
		}
		close(serverErr)
	}()

	// Wait for server to be ready.
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", flagPort)
	if err := waitForHealthy(baseURL, 10, 100*time.Millisecond); err != nil {
		return fmt.Errorf("server failed to start: %w", err)
	}

	// Signup: create admin account.
	token, err := doSignup(baseURL, email, password)
	if err != nil {
		return fmt.Errorf("signup: %w", err)
	}

	// Save CLI config.
	if err := saveConfig(&CLIConfig{
		Server: baseURL,
		Token:  token,
		Email:  email,
	}); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	// Create team.
	if err := doCreateTeam(baseURL, token, teamName); err != nil {
		return fmt.Errorf("create team: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Provisioned: logged in as %s, team %q created, server running on :%d\n", email, teamName, flagPort)

	// Block until server stops.
	if err := <-serverErr; err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	if err := st.Close(); err != nil {
		slog.Error("error closing database", "error", err)
	} else {
		slog.Info("database closed")
	}

	return nil
}

// waitForHealthy polls the health endpoint until it returns 200.
func waitForHealthy(baseURL string, attempts int, delay time.Duration) error {
	for i := range attempts {
		resp, err := http.Get(baseURL + "/api/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if i < attempts-1 {
			time.Sleep(delay)
		}
	}
	return fmt.Errorf("health check failed after %d attempts", attempts)
}

// doSignup creates an account and returns the auth token.
func doSignup(baseURL, email, password string) (string, error) {
	body, err := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	if err != nil {
		return "", fmt.Errorf("encoding request: %w", err)
	}

	req, err := http.NewRequest("POST", baseURL+"/api/auth/signup", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("connecting to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return "", fmt.Errorf("failed (%d): %s", resp.StatusCode, errResp["error"])
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}
	return result.Token, nil
}

// doCreateTeam creates a team using the given auth token.
func doCreateTeam(baseURL, token, name string) error {
	body, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		return fmt.Errorf("encoding request: %w", err)
	}

	req, err := http.NewRequest("POST", baseURL+"/api/teams", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("connecting to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("failed (%d): %s", resp.StatusCode, errResp["error"])
	}

	return nil
}
