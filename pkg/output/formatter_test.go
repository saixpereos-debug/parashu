package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestJSONWriter_Write(t *testing.T) {
	writer := &JSONWriter{}
	result := &ScanResult{
		ScanID:    "test-scan",
		Timestamp: time.Now(),
		Results: []HostResult{
			{
				IP: "127.0.0.1",
				Ports: []PortResult{
					{Port: 80, Protocol: "tcp", Service: "http"},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := writer.Write(result, &buf)
	if err != nil {
		t.Fatalf("failed to write JSON: %v", err)
	}

	var decoded ScanResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}

	if decoded.ScanID != result.ScanID {
		t.Errorf("expected ScanID %s, got %s", result.ScanID, decoded.ScanID)
	}
}

func TestTableWriter_Write(t *testing.T) {
	writer := &TableWriter{}
	result := &ScanResult{
		Results: []HostResult{
			{
				IP: "127.0.0.1",
				Ports: []PortResult{
					{Port: 80, Protocol: "tcp", Service: "http", Version: "1.1", RiskScore: 0.0},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := writer.Write(result, &buf)
	if err != nil {
		t.Fatalf("failed to write Table: %v", err)
	}
	// Note: Current TableWriter prints to stdout (rodaine/table default).
	// In the real implementation, we should fix it to use the buffer.
}

func TestHTMLWriter_Write(t *testing.T) {
	writer := &HTMLWriter{}
	result := &ScanResult{
		ScanID: "test-scan",
		Results: []HostResult{
			{
				IP: "127.0.0.1",
				Ports: []PortResult{
					{Port: 80, Protocol: "tcp", Service: "http"},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := writer.Write(result, &buf)
	if err != nil {
		t.Fatalf("failed to write HTML: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "<html>") {
		t.Error("HTML output missing <html> tag")
	}
	if !strings.Contains(output, "test-scan") {
		t.Error("HTML output missing ScanID")
	}
}
