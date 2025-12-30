package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"parashu/pkg/vuln"

	"github.com/spf13/cobra"
)

var (
	sourceFlag string
	forceFlag  bool
)

// dbCmd represents the db command
var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Manage the local vulnerability database",
	Long:  `Update, query, or check the status of the local offline vulnerability database.`,
}

var dbUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update the vulnerability database",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Updating vulnerability database (Source: %s, Force: %v)...\n", sourceFlag, forceFlag)
		db, err := vuln.NewDB()
		if err != nil {
			fmt.Printf("Error initializing DB: %v\n", err)
			os.Exit(1)
		}
		defer db.Close()

		if err := db.Update(sourceFlag, forceFlag); err != nil {
			fmt.Printf("Error updating DB: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Database updated successfully.")
	},
}

var dbStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show database status",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Database Status: Unknown (Not implemented)")
		// TODO: Check DB status
	},
}

var dbPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Show database file location",
	Run: func(cmd *cobra.Command, args []string) {
		home, _ := os.UserHomeDir()
		fmt.Println(filepath.Join(home, ".parashu", "parashu.db"))
	},
}

func init() {
	rootCmd.AddCommand(dbCmd)
	dbCmd.AddCommand(dbUpdateCmd)
	dbCmd.AddCommand(dbStatusCmd)
	dbCmd.AddCommand(dbPathCmd)

	dbUpdateCmd.Flags().StringVar(&sourceFlag, "source", "all", "Update source (all, osv, nvd)")
	dbUpdateCmd.Flags().BoolVar(&forceFlag, "force", false, "Force rebuild index")
}
