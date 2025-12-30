## ✨ Key Features

- **🚀 High Performance**: Built in Go with extreme concurrency for lightning-fast port discovery.
- **🔌 Plugin Architecture**: Easily extendable with custom scanners and banner grabbers.
- **💾 Offline-First**: Fully self-contained CVE and Exploit database for air-gapped security.
- **🛡️ Advanced Evasion**: 
    - **Timing Profiles**: Nmap-style `-T0` (Paranoid) to `-T5` (Insane) presets.
    - **Ping Suppression**: Silent host discovery via `-n`.
    - **Proxy Support**: Full SOCKS5 proxy routing for anonymous scanning.
    - **Packet Padding**: Append random data to probes to evade length-based IDS signatures.
- **🕵️ Red Team Tooling**:
    - **Layer Scanning**: Granular scanning across all 7 OSI layers (Physical to Application).
    - **Exploit Intelligence**: Automated matching of vulnerabilities to verified exploit scripts.
    - **Prioritized Results**: Smart scoring based on exploit verification and Metasploit availability.

## 🛠 Usage Examples

### 1. Basic & Range Scanning
```bash
# Scan Top 1000 ports
parashu scan 192.168.1.10

# Scan all 65k ports on a CIDR range
parashu scan 10.0.0.0/24 --ports all
```

### 2. Stealth & Evasion
```bash
# Paranoid timing through a proxy with packet padding
parashu scan 192.168.1.10 -T0 --proxies 127.0.0.1:9050 --data-length 128 -n
```

### 3. Red Team Operations
```bash
# Layer-specific scan for Application layer endpoints
parashu layer-scan --layer application --target 192.168.1.50

# Vulnerability scan with automated exploit matching
parashu scan 10.0.1.0/24 --exploit-match
```

### 4. Exploit Intelligence
```bash
# Sync local exploit database
parashu exploit sync

# Search and retrieve exploit details
parashu exploit search websphere
parashu exploit get 16929
```

## 📊 Documentation
For a deep dive into all commands and advanced configurations, check out the [User Manual](USER_MANUAL.md).
