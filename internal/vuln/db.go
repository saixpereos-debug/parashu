package vuln

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

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
