package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

// Config holds the application configuration
type Config struct {
	Ports          string        `mapstructure:"ports"`
	Timeout        time.Duration `mapstructure:"timeout"`
	RateLimit      int           `mapstructure:"rate-limit"`
	Output         string        `mapstructure:"output"`
	OutputFile     string        `mapstructure:"output-file"`
	OnlineFallback bool          `mapstructure:"online-fallback"`
	APIKey         string        `mapstructure:"api-key"`
}

// LoadConfig reads configuration from file and environment variables
func LoadConfig() (*Config, error) {
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SaveConfig writes the current configuration to the config file
func SaveConfig() error {
	filename := viper.ConfigFileUsed()
	if filename == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		filename = filepath.Join(home, ".parashu.yaml")
	}
	return viper.WriteConfigAs(filename)
}

// SetDefaultValues sets the default values for the configuration
func SetDefaultValues() {
	viper.SetDefault("ports", "top1000")
	viper.SetDefault("timeout", "2s")
	viper.SetDefault("rate-limit", 100)
	viper.SetDefault("output", "table")
	viper.SetDefault("online-fallback", false)
}

// Set updates a specific configuration key
func Set(key string, value interface{}) {
	viper.Set(key, value)
}

// GetPath returns the path to the configuration file
func GetPath() string {
	return viper.ConfigFileUsed()
}

// PrintConfig prints the current configuration
func PrintConfig() {
	fmt.Println("Current Configuration:")
	for key, value := range viper.AllSettings() {
		fmt.Printf("  %s: %v\n", key, value)
	}
}
