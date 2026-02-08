package cmd

import (
	"github.com/spf13/cobra"
)

var Version = "dev"

var rootCmd = &cobra.Command{
	Use:     "sneaker",
	Short:   "One-time secret exchange",
	Version: Version,
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
