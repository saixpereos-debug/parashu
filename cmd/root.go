package cmd

import (
	"os"

	"github.com/saixpereos-debug/parashu/internal/config"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var cfg *config.Config

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "parashu",
	Short: "A fast, offline-first network vulnerability scanner",
	Long: `Parashu is a modern, high-performance vulnerability scanner tailored for offline environments.
It focuses on accurate version detection and risk-based vulnerability reporting.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	config.SetDefaultValues()

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.parashu.yaml)")
	rootCmd.PersistentFlags().String("output", "table", "Output format (table, json, html)")
	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".parashu" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".parashu")
	}

	viper.AutomaticEnv() // read in environment variables that match
	viper.SetEnvPrefix("PARASHU")

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		// fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	// Load config into struct
	var err error
	cfg, err = config.LoadConfig()
	if err != nil {
		// fmt.Fprintf(os.Stderr, "Warning: could not load config: %v\n", err)
	}
}
