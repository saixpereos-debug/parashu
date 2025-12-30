package adaptive

import "time"

// ProfileName defines the available scanning profiles
type ProfileName string

const (
	ProfileStealth    ProfileName = "stealth"
	ProfileBalanced   ProfileName = "balanced"
	ProfileAggressive ProfileName = "aggressive"

	// Nmap-style Timing Profiles
	T0 ProfileName = "0" // Paranoid
	T1 ProfileName = "1" // Sneaky
	T2 ProfileName = "2" // Polite
	T3 ProfileName = "3" // Normal (Balanced)
	T4 ProfileName = "4" // Aggressive
	T5 ProfileName = "5" // Insane
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
	case ProfileStealth, T1: // Sneaky / Stealth
		return ScanConfig{
			InitialConcurrency: 1,
			MinTimeout:         1500 * time.Millisecond,
			MaxTimeout:         10 * time.Second,
			RetryCount:         0,
			ScanDelay:          15 * time.Second,
		}
	case T0: // Paranoid
		return ScanConfig{
			InitialConcurrency: 1,
			MinTimeout:         5 * time.Second,
			MaxTimeout:         30 * time.Second,
			RetryCount:         0,
			ScanDelay:          5 * time.Minute,
		}
	case T2: // Polite
		return ScanConfig{
			InitialConcurrency: 1,
			MinTimeout:         500 * time.Millisecond,
			MaxTimeout:         5 * time.Second,
			RetryCount:         0,
			ScanDelay:          400 * time.Millisecond,
		}
	case ProfileAggressive, T4: // Aggressive
		return ScanConfig{
			InitialConcurrency: 100,
			MinTimeout:         300 * time.Millisecond,
			MaxTimeout:         1500 * time.Millisecond,
			RetryCount:         2,
			ScanDelay:          0,
		}
	case T5: // Insane
		return ScanConfig{
			InitialConcurrency: 300,
			MinTimeout:         50 * time.Millisecond,
			MaxTimeout:         500 * time.Millisecond,
			RetryCount:         3,
			ScanDelay:          0,
		}
	case ProfileBalanced, T3: // Balanced / Normal
		fallthrough
	default:
		return ScanConfig{
			InitialConcurrency: 50,
			MinTimeout:         500 * time.Millisecond,
			MaxTimeout:         2 * time.Second,
			RetryCount:         1,
			ScanDelay:          0,
		}
	}
}
