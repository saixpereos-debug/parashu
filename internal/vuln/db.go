package vuln

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// DBClient handles interactions with the vulnerability database
type DBClient struct {
	db *sql.DB
}

// NewDBClient initializes a connection and ensures the schema exists
func NewDBClient(path string) (*DBClient, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %w", err)
	}

	client := &DBClient{db: db}
	if err := client.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to init schema: %w", err)
	}

	return client, nil
}

// initSchema creates the necessary tables if they don't exist
func (c *DBClient) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT PRIMARY KEY,
		summary TEXT,
		details TEXT,
		published_at DATETIME,
		modified_at DATETIME,
		severity TEXT,
		score REAL
	);

	CREATE TABLE IF NOT EXISTS cpe_index (
		cpe TEXT,
		vuln_id TEXT,
		version_start TEXT,
		version_end TEXT,
		FOREIGN KEY(vuln_id) REFERENCES vulnerabilities(id)
	);
	
	CREATE INDEX IF NOT EXISTS idx_cpe ON cpe_index(cpe);
	`
	_, err := c.db.Exec(schema)
	return err
}

// Vulnerability represents a security issue
type Vulnerability struct {
	ID       string
	Summary  string
	Severity string
	Score    float64
}

// GetVulnerabilities returns vulns for a given CPE
func (c *DBClient) GetVulnerabilities(cpe string) ([]Vulnerability, error) {
	query := `
		SELECT v.id, v.summary, v.severity, v.score 
		FROM vulnerabilities v
		JOIN cpe_index i ON v.id = i.vuln_id
		WHERE i.cpe = ?
	`
	rows, err := c.db.Query(query, cpe)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []Vulnerability
	for rows.Next() {
		var v Vulnerability
		if err := rows.Scan(&v.ID, &v.Summary, &v.Severity, &v.Score); err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}

// Close closes the database connection
func (c *DBClient) Close() error {
	return c.db.Close()
}
