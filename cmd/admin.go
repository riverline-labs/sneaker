package cmd

import (
	"github.com/spf13/cobra"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Server administration commands",
}

func init() {
	rootCmd.AddCommand(adminCmd)
}
