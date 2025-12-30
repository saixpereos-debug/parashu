# 🔱 Parashu User Manual

Parashu is a high-performance, modern Go-based vulnerability scanner designed for environments where accuracy, speed, and offline capability are paramount. It pairs active scanning with a local, highly-optimized vulnerability database.

---

## 🚀 Getting Started

To see all available commands, run:
```bash
parashu --help
```

### 📦 Installation
If you have Go installed:
```bash
go install github.com/saixpereos-debug/parashu@latest
```

---

## 💾 Database Setup (Offline Intel)

Parashu relies on a local database for instant, silent vulnerability and exploit lookups.

### 1. Vulnerability Definitions (CVE/CPE)
Update the core vulnerability database:
```bash
parashu db update
```

### 2. Exploit Database (Red Team Intel)
Sync tens of thousands of exploit metadata from Exploit-DB:
```bash
parashu exploit sync
```

---

## 🔍 Scanning Targets

The `scan` command is the flagship feature. It supports single targets, CIDRs, and lists.

### Basic Usage
```bash
# Single Target
parashu scan 192.168.1.1

# CIDR Range (Automated expansion)
parashu scan 10.0.0.0/24

# Hostnames and Lists
parashu scan host.internal,192.168.1.5,192.168.1.6
```

### Advanced Scan Configuration
| Flag | Description | Example |
| :--- | :--- | :--- |
| `--ports` | Specify ports (top1000, all, range, list) | `--ports 80,443,8080-8088` |
| `--profile` | Concurrency/Timing (stealth, balanced, aggressive) | `--profile aggressive` |
| `-f, --file` | Scan targets from a text file | `-f targets.txt` |
| `--output` | report format (table, json, html) | `--output html` |
| `--output-file`| Save results to a file | `--output-file scan.html` |

---

## 🛡️ Stealth & Evasion

Designed for Red Teams, Parashu includes advanced logic to bypass IDS/IPS and Firewalls.

### 1. Timing Profiles (Nmap Style)
Control the speed and noise level of your scan:
- `-T0` (Paranoid): Extremely slow, serial probes to bypass nearly all detection.
- `-T1` (Sneaky): Slow and methodical.
- `-T2` (Polite): Low-bandwidth, waits between probes.
- `-T3` (Normal): The default balanced experience.
- `-T4` (Aggressive): Fast, assumes a stable and noise-tolerant network.
- `-T5` (Insane): Maximum speed, likely to be detected.

```bash
parashu scan 192.168.1.10 -T1
```

### 2. Evasion Tactics
- **Ping Suppression (`-n` / `--no-ping`)**: Skip host discovery. Useful for targets protected by "silent" firewalls.
- **Proxy Routing (`--proxies`)**: Route scans through SOCKS5 (e.g., Tor or SSH tunnels).
- **Packet Padding (`--data-length`)**: Append random data to probes to bypass length-based signature detection.

```bash
parashu scan 192.168.1.10 -n --proxies 127.0.0.1:9050 --data-length 150
```

---

## 🕵️ Red Team: Layer Specific Scanning

Beyond TCP/UDP port scanning, Parashu can perform specialized scans across the 7 OSI layers.

### The `layer-scan` Command
Use specialized logic for different attack surfaces:
```bash
parashu layer-scan --layer [name] --target [host]
```

| Layer | Focus | Detection Logic |
| :--- | :--- | :--- |
| `datalink` | VLANs/ARP | Detects trunking ports and VLAN tagging. |
| `network` | IP/Fragmentation | Identifies IP fragmentation handling and IPv6 capabilities. |
| `transport` | TCP/UDP Anomalies | Scans using ACK/FIN/NULL probes to find filtered ports. |
| `application`| Software Services | Detects SSO endpoints, Docker APIs, and K8s clusters. |

---

## 💣 Exploit Intelligence

Parashu doesn't just find vulnerabilities; it provides the intel to exploit them.

### Automated Exploit Matching
During any scan, use the `--exploit-match` flag to cross-reference discovered services with local exploits:
```bash
parashu scan 192.168.1.50 --exploit-match
```

### The `exploit` Subcommand
- **Search**: `parashu exploit search wordpress 5.x`
- **Retrieve**: `parashu exploit get 16929` (Returns metadata and local code path)
- **Priority**: Exploits are automatically ranked by **Verification**, **Metasploit availability**, and **Recency**.

---

## 💡 Pro Tips

1. **Automation**: Use `--output json` and pipe into `jq` to build custom reporting streams.
2. **Persistence**: Use `parashu config set` to save your API keys and default profiles.
3. **Quiet Mode**: For maximum stealth, use `-T0 -n --banners-only`. This avoids vulnerability lookups and keeps traffic to a minimum.

---

*Parashu - Precise. Silent. Deadly.*
