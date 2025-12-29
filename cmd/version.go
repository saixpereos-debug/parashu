package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version and build info",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Parashu v1.0.0")
		// TODO: Add build tags, date, commit hash
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
