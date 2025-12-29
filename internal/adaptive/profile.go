package adaptive

import "time"

// ProfileName defines the available scanning profiles
type ProfileName string

const (
	ProfileStealth    ProfileName = "stealth"
	ProfileBalanced   ProfileName = "balanced"
	ProfileAggressive ProfileName = "aggressive"
)

// ScanConfig holds the parameters for a scan that can change adaptively
type ScanConfig struct {
	InitialConcurrency int
	MinTimeout         time.Duration
	MaxTimeout         time.Duration
	RetryCount         int
	ScanDelay          time.Duration
}

// GetProfile returns a pre-defined ScanConfig for a given profile name
func GetProfile(name string) ScanConfig {
	switch ProfileName(name) {
	case ProfileStealth:
		return ScanConfig{
			InitialConcurrency: 10,
			MinTimeout:         1500 * time.Millisecond,
			MaxTimeout:         5 * time.Second,
			RetryCount:         0,
			ScanDelay:          500 * time.Millisecond,
		}
	case ProfileAggressive:
		return ScanConfig{
			InitialConcurrency: 500,
			MinTimeout:         200 * time.Millisecond,
			MaxTimeout:         1 * time.Second,
			RetryCount:         2,
			ScanDelay:          0,
		}
	case ProfileBalanced:
		fallthrough
	default:
		return ScanConfig{
			InitialConcurrency: 100,
			MinTimeout:         500 * time.Millisecond,
			MaxTimeout:         2 * time.Second,
			RetryCount:         1,
			ScanDelay:          50 * time.Millisecond,
		}
	}
}
