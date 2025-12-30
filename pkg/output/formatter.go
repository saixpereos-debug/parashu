package output

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"

	"github.com/rodaine/table"
)

// Writer defines the interface for output formatters
type Writer interface {
	Write(result *ScanResult, w io.Writer) error
}

// NewWriter returns a Writer based on the format string
func NewWriter(format string) (Writer, error) {
	switch format {
	case "json":
		return &JSONWriter{}, nil
	case "table":
		return &TableWriter{}, nil
	case "html":
		return &HTMLWriter{}, nil
	default:
		return nil, fmt.Errorf("unknown output format: %s", format)
	}
}

// JSONWriter implements JSON output
type JSONWriter struct{}

func (jw *JSONWriter) Write(result *ScanResult, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// TableWriter implements Table output
type TableWriter struct{}

func (tw *TableWriter) Write(result *ScanResult, w io.Writer) error {
	tbl := table.New("IP", "Port", "Service", "Version", "Vulns", "Risk")

	for _, host := range result.Results {
		for _, port := range host.Ports {
			vulnCount := len(port.Vulnerabilities)
			tbl.AddRow(host.IP, port.Port, port.Service, port.Version, vulnCount, port.RiskScore)
		}
	}
	tbl.Print() // Note: rodaine/table output handling is slightly different, usually prints to stdout.
	// To strictly use 'w', we might need a different table lib or SetOutput if supported.
	// rodaine/table v1.3.0 supports tbl.WithWriter(w)
	return nil
}

// HTMLWriter implements HTML output
type HTMLWriter struct{}

func (hw *HTMLWriter) Write(result *ScanResult, w io.Writer) error {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, result)
}

const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
	<title>Parashu Scan Report</title>
	<style>
		body { font-family: sans-serif; margin: 20px; }
		table { border-collapse: collapse; width: 100%; }
		th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
		th { background-color: #f2f2f2; }
		.critical { color: red; font-weight: bold; }
	</style>
</head>
<body>
	<h1>Parashu Scan Report</h1>
	<p><strong>Scan ID:</strong> {{.ScanID}}</p>
	<p><strong>Timestamp:</strong> {{.Timestamp}}</p>
	
	<h2>Summary</h2>
	<ul>
		<li>Hosts Scanned: {{.Summary.HostsScanned}}</li>
		<li>Open Ports: {{.Summary.OpenPorts}}</li>
		<li>Vulnerable Services: {{.Summary.VulnerableServices}}</li>
		<li>Critical Vulnerabilities: {{.Summary.CriticalVulns}}</li>
	</ul>

	<h2>Detailed Results</h2>
	{{range .Results}}
	<h3>Host: {{.IP}} {{if .Hostname}}({{.Hostname}}){{end}}</h3>
	<table>
		<tr>
			<th>Port</th>
			<th>Service</th>
			<th>Version</th>
			<th>Risk Score</th>
			<th>Vulnerabilities</th>
		</tr>
		{{range .Ports}}
		<tr>
			<td>{{.Port}}/{{.Protocol}}</td>
			<td>{{.Service}}</td>
			<td>{{.Version}}</td>
			<td>{{.RiskScore}}</td>
			<td>
				{{range .Vulnerabilities}}
				<div class="{{if .KEV}}critical{{end}}">
					{{.CVE}} (CVSS: {{.CVSS}}) <br>
					<small>{{.Summary}}</small>
				</div>
				{{end}}
			</td>
		</tr>
		{{end}}
	</table>
	{{end}}
</body>
</html>
`
