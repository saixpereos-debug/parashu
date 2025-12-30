package vuln

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewDB(t *testing.T) {
	// Create a temporary directory for the test DB
	tmpDir, err := os.MkdirTemp("", "parashu-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Override home directory for the test
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	db, err := NewDB()
	if err != nil {
		t.Fatalf("failed to create new DB: %v", err)
	}
	defer db.Close()

	// Check if the DB file was created
	dbPath := filepath.Join(tmpDir, ".parashu", "parashu.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("DB file was not created at %s", dbPath)
	}
}

func TestDB_Update(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "parashu-test-*")
	defer os.RemoveAll(tmpDir)
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	db, _ := NewDB()
	defer db.Close()

	err := db.Update("mock-source", false)
	if err != nil {
		t.Fatalf("failed to update DB: %v", err)
	}

	// Verify that the mock record exists
	var count int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM cves WHERE id = 'CVE-2023-MOCK'").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query DB: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 mock record, got %d", count)
	}
}
