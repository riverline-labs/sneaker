package cmd

import (
	"github.com/spf13/cobra"
)

var teamCmd = &cobra.Command{
	Use:   "team",
	Short: "Manage teams",
}

func init() {
	rootCmd.AddCommand(teamCmd)
}
