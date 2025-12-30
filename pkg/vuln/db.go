package vuln

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // Import sqlite driver
)

// DB represents the vulnerability database
type DB struct {
	conn *sql.DB
}

// NewDB opens or creates the vulnerability database
func NewDB() (*DB, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dbPath := filepath.Join(home, ".parashu", "parashu.db")

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	return &DB{conn: db}, nil
}

func initSchema(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS cves (
		id TEXT PRIMARY KEY,
		description TEXT,
		severity TEXT,
		cvss REAL
	);
	CREATE TABLE IF NOT EXISTS cpes (
		cpe TEXT,
		cve_id TEXT,
		FOREIGN KEY(cve_id) REFERENCES cves(id)
	);
	CREATE INDEX IF NOT EXISTS idx_cpe ON cpes(cpe);
	CREATE TABLE IF NOT EXISTS redteam_rules (
		id TEXT PRIMARY KEY,
		layer TEXT,
		name TEXT,
		description TEXT,
		signature TEXT,
		remediation TEXT,
		severity TEXT
	);
	CREATE TABLE IF NOT EXISTS exploits (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		edb_id INTEGER,
		title TEXT,
		description TEXT,
		author TEXT,
		type TEXT,
		platform TEXT,
		date TEXT,
		verified INTEGER,
		tags TEXT,
		code_path TEXT,
		cves TEXT,
		cpes TEXT,
		port INTEGER,
		metasploit INTEGER
	);
	`
	_, err := db.Exec(query)
	return err
}

// Update downloads the latest vulnerability definitions (Stub)
func (d *DB) Update(source string, force bool) error {
	// TODO: meaningful update logic (download format, etc.)
	fmt.Printf("Mock: Downloading definitions from %s (force=%v)...\n", source, force)

	// Mock Insert
	_, err := d.conn.Exec(`INSERT OR REPLACE INTO cves (id, description, severity, cvss) VALUES ('CVE-2023-MOCK', 'Mock Vulnerability', 'HIGH', 9.8)`)
	return err
}

// Close closes the database connection
func (d *DB) Close() error {
	return d.conn.Close()
}

// InsertExploit adds an exploit to the database
func (d *DB) InsertExploit(exploit Exploit) error {
	tags, _ := json.Marshal(exploit.Tags)
	cves, _ := json.Marshal(exploit.CVEs)
	cpes, _ := json.Marshal(exploit.CPEs)

	_, err := d.conn.Exec(
		"INSERT OR REPLACE INTO exploits (edb_id, title, description, author, type, platform, date, verified, tags, code_path, cves, cpes, port, metasploit) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		exploit.EDBID, exploit.Title, exploit.Description, exploit.Author,
		exploit.Type, exploit.Platform, exploit.Date.Format(time.RFC3339),
		iif(exploit.Verified, 1, 0), string(tags), exploit.CodePath,
		string(cves), string(cpes), exploit.Port, iif(exploit.Metasploit, 1, 0),
	)
	return err
}

// GetExploit retrieves a specific exploit by ID
func (d *DB) GetExploit(id int) (*Exploit, error) {
	var exploit Exploit
	var dateStr, tagsStr, cvesStr, cpesStr string
	var verifiedInt, msInt int

	err := d.conn.QueryRow(
		"SELECT id, edb_id, title, description, author, type, platform, date, verified, tags, code_path, cves, cpes, port, metasploit FROM exploits WHERE id = ?",
		id,
	).Scan(
		&exploit.ID, &exploit.EDBID, &exploit.Title, &exploit.Description,
		&exploit.Author, &exploit.Type, &exploit.Platform, &dateStr,
		&verifiedInt, &tagsStr, &exploit.CodePath, &cvesStr, &cpesStr,
		&exploit.Port, &msInt,
	)
	if err != nil {
		return nil, err
	}

	exploit.Date, _ = time.Parse(time.RFC3339, dateStr)
	exploit.Verified = (verifiedInt == 1)
	exploit.Metasploit = (msInt == 1)
	json.Unmarshal([]byte(tagsStr), &exploit.Tags)
	json.Unmarshal([]byte(cvesStr), &exploit.CVEs)
	json.Unmarshal([]byte(cpesStr), &exploit.CPEs)

	return &exploit, nil
}

// SearchExploits performs a text search across title, description, and tags
func (d *DB) SearchExploits(query string) ([]Exploit, error) {
	q := "%" + query + "%"
	rows, err := d.conn.Query(
		"SELECT id, edb_id, title, description, author, type, platform, date, verified, tags, code_path, cves, cpes, port, metasploit FROM exploits WHERE title LIKE ? OR description LIKE ? OR tags LIKE ?",
		q, q, q,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exploits []Exploit
	for rows.Next() {
		var e Exploit
		var dateStr, tagsStr, cvesStr, cpesStr string
		var verifiedInt, msInt int

		err := rows.Scan(
			&e.ID, &e.EDBID, &e.Title, &e.Description,
			&e.Author, &e.Type, &e.Platform, &dateStr,
			&verifiedInt, &tagsStr, &e.CodePath, &cvesStr, &cpesStr,
			&e.Port, &msInt,
		)
		if err != nil {
			return nil, err
		}

		e.Date, _ = time.Parse(time.RFC3339, dateStr)
		e.Verified = (verifiedInt == 1)
		e.Metasploit = (msInt == 1)
		json.Unmarshal([]byte(tagsStr), &e.Tags)
		json.Unmarshal([]byte(cvesStr), &e.CVEs)
		json.Unmarshal([]byte(cpesStr), &e.CPEs)

		exploits = append(exploits, e)
	}
	return exploits, nil
}

// GetExploitsByCVE searches for exploits matching a specific CVE
func (d *DB) GetExploitsByCVE(cve string) ([]ExploitMatch, error) {
	q := "%" + cve + "%"
	rows, err := d.conn.Query("SELECT id FROM exploits WHERE cves LIKE ?", q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []ExploitMatch
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err == nil {
			matches = append(matches, ExploitMatch{
				ExploitID:  id,
				Confidence: 95,
				MatchType:  "cve",
				Evidence:   fmt.Sprintf("Direct CVE match: %s", cve),
			})
		}
	}
	return matches, nil
}

// GetExploitByEDBID retrieves a specific exploit by its EDB-ID
func (d *DB) GetExploitByEDBID(edbID int) (*Exploit, error) {
	var exploit Exploit
	var dateStr, tagsStr, cvesStr, cpesStr string
	var verifiedInt, msInt int

	err := d.conn.QueryRow(
		"SELECT id, edb_id, title, description, author, type, platform, date, verified, tags, code_path, cves, cpes, port, metasploit FROM exploits WHERE edb_id = ?",
		edbID,
	).Scan(
		&exploit.ID, &exploit.EDBID, &exploit.Title, &exploit.Description,
		&exploit.Author, &exploit.Type, &exploit.Platform, &dateStr,
		&verifiedInt, &tagsStr, &exploit.CodePath, &cvesStr, &cpesStr,
		&exploit.Port, &msInt,
	)
	if err != nil {
		return nil, err
	}

	exploit.Date, _ = time.Parse(time.RFC3339, dateStr)
	exploit.Verified = (verifiedInt == 1)
	exploit.Metasploit = (msInt == 1)
	json.Unmarshal([]byte(tagsStr), &exploit.Tags)
	json.Unmarshal([]byte(cvesStr), &exploit.CVEs)
	json.Unmarshal([]byte(cpesStr), &exploit.CPEs)

	return &exploit, nil
}

func iif(cond bool, a, b int) int {
	if cond {
		return a
	}
	return b
}
