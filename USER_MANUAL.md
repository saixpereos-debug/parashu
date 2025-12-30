# Parashu User Manual

Parashu is a high-performance, modern Go-based vulnerability scanner designed for environments where accuracy, speed, and offline capability are paramount. This manual covers all features and commands to ensure you get the most out of the tool.

---

## 🚀 Getting Started

To see all available commands, run:
```bash
parashu --help
```

---

## 🔍 Scanning Targets

The `scan` command is the core of Parashu. It allows you to scan IPs, CIDR ranges, or hostnames.

### Basic Scan
```bash
parashu scan 192.168.1.1
```

### Scan with CIDR or List
```bash
parashu scan 10.0.0.0/24
parashu scan host1.local,host2.local
```

### Scan from File
Scan multiple targets from a text file (one target per line):
```bash
parashu scan -f targets.txt
```

---

## ⚙️ Scan Options

### Port Selection
Use the `--ports` flag to specify which ports to scan:
- `top1000` (default): Most common 1000 ports.
- `all`: All 65,535 ports.
- `range`: e.g., `80-443`.
- `list`: e.g., `22,80,443`.

```bash
parashu scan 192.168.1.1 --ports 80,443,8080
```

### Scan Profiles
Profiles adjust concurrency and timeouts for different scenarios:
- `stealth`: Slow and quiet (avoids detection).
- `balanced` (default): Good mix of speed and accuracy.
- `aggressive`: Fast, but may be noisy or miss ports on unstable networks.

```bash
parashu scan 192.168.1.1 --profile stealth
```

### Advanced Performance Flags
- `--timeout`: Set custom timeout per port (e.g., `2s`).
- `--rate-limit`: Set concurrent connections limit (e.g., `100`).

---

## 📊 Output Formats

Parashu supports multiple output formats for easy integration or reporting.

- `table` (default): Clean CLI table.
- `json`: Structured data for automation.
- `html`: Professional report for sharing with stakeholders.

```bash
parashu scan 192.168.1.1 --output html --output-file report.html
```

---

## 💾 Vulnerability Database

Parashu uses a local SQLite database for offline CVE lookups.

### Update Database
Requires internet access to download the latest definitions:
```bash
parashu db update
```

### Check DB Status & Path
```bash
parashu db status
parashu db path
```

---

## 🔧 Configuration Management

You can save your preferred settings so you don't have to pass them every time.

### Set a Config Value
```bash
parashu config set output json
parashu config set ports all
```

### View Current Config
```bash
parashu config view
parashu config path
```

---

## 🛑 Filtering & Exclusion

Exclude specific targets from a scan:
- `--exclude`: Comma-separated list.
- `--exclude-file`: File with list of exclusions.

```bash
parashu scan 10.0.0.0/24 --exclude 10.0.0.1,10.0.0.2
```

---

## 🛡️ Stealth & Evasion (Advanced)

New in v1.1.0: Advanced features to evade firewalls and IDS.

### Ping Suppression
Skip host discovery/resolution to avoid early detection:
```bash
parashu scan 192.168.1.1 -n
# or
parashu scan 192.168.1.1 --no-ping
```

### Advanced Timing (Nmap-style)
Use shorthand timing profiles:
- `-T0`: Paranoid (extremely slow, serial)
- `-T1`: Sneaky
- `-T2`: Polite
- `-T3`: Normal (default)
- `-T4`: Aggressive
- `-T5`: Insane (very fast)

```bash
parashu scan 192.168.1.1 -T0
```

### Proxy Routing
Route your scans through SOCKS5 proxies:
```bash
parashu scan 192.168.1.1 --proxies 127.0.0.1:9050
```

### Packet Padding (Evasion)
Add extra data to your probe packets to evade length-based signatures:
```bash
parashu scan 192.168.1.1 --data-length 200
```

### Banners and Fallbacks
- `--banners-only`: Only grab service banners, skip vulnerability lookups.
- `--online-fallback`: Query online APIs if a service is not found in the local DB.
- `--api-key`: Provide your API key for online enrichment.

---

## 🛠️ Exploit Database Integration

Parashu includes a powerful exploit matching engine that cross-references discovered vulnerabilities with known exploit scripts from Exploit-DB and other sources.

### Syncing the Database
To download the latest exploit metadata and scripts (requires internet):
```bash
parashu exploit sync
```

### Searching for Exploits
Search the local database for specific keywords:
```bash
parashu exploit search apache 2.4.49
```

### Matching During Scans
Automatically find matching exploits for discovered vulnerabilities:
```bash
parashu scan 192.168.1.10 --exploit-match
```

### Retrieving Exploit Code
Get the details and local code path for a specific exploit:
```bash
parashu exploit get 16929
```

---

## 🛡️ Advanced Red Team Implementation
...
