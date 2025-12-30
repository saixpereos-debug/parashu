package vuln

import "time"

// Exploit represents an entry in an exploit database
type Exploit struct {
	ID          int       `json:"id"`
	EDBID       int       `json:"edb_id"` // Exploit-DB ID
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Author      string    `json:"author"`
	Type        string    `json:"type"`     // webapps, remote, local, etc.
	Platform    string    `json:"platform"` // linux, windows, etc.
	Date        time.Time `json:"date"`
	Verified    bool      `json:"verified"`
	Tags        []string  `json:"tags"`
	CodePath    string    `json:"code_path"`  // Local path to exploit code
	CVEs        []string  `json:"cves"`       // CVEs this exploit targets
	CPEs        []string  `json:"cpes"`       // CPEs this exploit targets
	Port        int       `json:"port"`       // Default port if applicable
	Metasploit  bool      `json:"metasploit"` // Available in Metasploit
}

// ExploitMatch represents a link between a vulnerability and an exploit
type ExploitMatch struct {
	VulnerabilityID string
	ExploitID       int
	Confidence      int    // 0-100
	MatchType       string // "cve", "cpe", "banner", "port"
	Evidence        string // What matched
}

// PrioritizedExploit combines exploit data with match confidence and a calculated priority
type PrioritizedExploit struct {
	Exploit  Exploit
	Match    ExploitMatch
	Priority int
}
