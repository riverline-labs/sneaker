package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// CLIConfig holds the CLI client configuration (server URL and auth token).
type CLIConfig struct {
	Server string `json:"server"`
	Token  string `json:"token"`
	Email  string `json:"email,omitempty"`
}

// configDir returns the path to the sneaker config directory.
func configDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("finding config directory: %w", err)
	}
	return filepath.Join(dir, "sneaker"), nil
}

// configPath returns the path to the sneaker config file.
func configPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// loadConfig reads the CLI config from disk.
// Returns a clear error if not logged in.
func loadConfig() (*CLIConfig, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("not logged in: run 'sneaker login --server URL' first")
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg CLIConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}

// identityKeyPath returns the path to the AGE identity key file.
func identityKeyPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "identity.key"), nil
}

// saveConfig writes the CLI config to disk with restricted permissions.
func saveConfig(cfg *CLIConfig) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	path := filepath.Join(dir, "config.json")
	return os.WriteFile(path, data, 0600)
}
