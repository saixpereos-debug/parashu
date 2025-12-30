package cmd

import (
	"fmt"

	"github.com/saixpereos-debug/parashu/internal/config"

	"github.com/spf13/cobra"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management",
	Long:  `Manage the tool's configuration settings.`,
}

var configSetCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Set a configuration value",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		value := args[1]

		validKeys := []string{"ports", "rate-limit", "output", "online-fallback"}
		isValid := false
		for _, k := range validKeys {
			if k == key {
				isValid = true
				break
			}
		}

		if !isValid {
			// Warn but allow setting? Spec implies strictness or generic?
			// "parashu config set ports top1000"
			// Let's allow but maybe validKeys is better for UX.
			// For now, allow it to be flexible or check against known keys.
		}

		config.Set(key, value)
		err := config.SaveConfig()
		if err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			return
		}
		fmt.Printf("Configuration updated: %s = %s\n", key, value)
	},
}

var configViewCmd = &cobra.Command{
	Use:   "view",
	Short: "View current configuration",
	Run: func(cmd *cobra.Command, args []string) {
		config.PrintConfig()
	},
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Show config file location",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(config.GetPath())
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configViewCmd)
	configCmd.AddCommand(configPathCmd)
}
