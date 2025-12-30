package output

import "time"

// ScanResult represents the top-level output structure
type ScanResult struct {
	ScanID    string       `json:"scan_id"`
	Timestamp time.Time    `json:"timestamp"`
	Targets   []string     `json:"targets"`
	Results   []HostResult `json:"results"`
	Summary   ScanSummary  `json:"summary"`
}

// HostResult represents findings for a single host
type HostResult struct {
	IP       string       `json:"ip"`
	Hostname string       `json:"hostname"`
	Ports    []PortResult `json:"ports"`
}

// PortResult represents a single open port and its details
type PortResult struct {
	Port            int     `json:"port"`
	Protocol        string  `json:"protocol"`
	Service         string  `json:"service"`
	Banner          string  `json:"banner"`
	Version         string  `json:"version"`
	CPE             string  `json:"cpe"`
	Vulnerabilities []Vuln  `json:"vulnerabilities"`
	RiskScore       float64 `json:"risk_score"`
}

// Vuln represents a specific vulnerability
type Vuln struct {
	CVE        string   `json:"cve"`
	CVSS       float64  `json:"cvss"`
	EPSS       float64  `json:"epss"`
	KEV        bool     `json:"kev"`
	Summary    string   `json:"summary"`
	References []string `json:"references"`
}

// ScanSummary provides high-level metrics
type ScanSummary struct {
	HostsScanned       int `json:"hosts_scanned"`
	OpenPorts          int `json:"open_ports"`
	VulnerableServices int `json:"vulnerable_services"`
	CriticalVulns      int `json:"critical_vulns"`
}
