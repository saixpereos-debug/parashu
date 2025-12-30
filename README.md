# Parashu
**Offline-First Network Service Vulnerability Scanner**

Parashu is a high-performance, Modern Go-based vulnerability scanner designed for environments where accuracy, speed, and offline capability are paramount. It pairs active scanning with a local, highly-optimized vulnerability database.

## When to Use Parashu

Parashu excels in scenarios where traditional online-dependent scanners struggle:

### 🔒 Air-Gapped & Secure Networks
**The Challenge:** High-security zones (defense, finance, critical infrastructure) often have no internet access, breaking scanners that rely on real-time API queries.
**Parashu Solution:** Uses a fully self-contained local database. Update the DB on a connected machine, transfer the binary + DB file, and scan without a single outbound packet.

### 🚀 CI/CD Pipelines
**The Challenge:** VAPT stages in pipelines need to be fast and deterministic. Waiting for external NVD API rate limits or network latency slows down builds.
**Parashu Solution:** Hits a local SQLite database for instant CVE lookups, ensuring consistent execution times and no external dependencies.

### 🕵️ Stealth Red Teaming
**The Challenge:** Constant DNS queries and HTTP requests to vulnerability feeds during a scan can trigger SOC alerts and reveal your toolkit's activity.
**Parashu Solution:** Silent operation. Only traffic sent is to the direct target. No noise, no leaks.

### ⚡ Rapid Triage
**The Challenge:** You need to scan a /24 subnet in minutes, not hours, to identify low-hanging fruit (known CVEs in unpatched services).
**Parashu Solution:** Highly concurrent (Go routines), optimized port scanning, and instant banner-to-CPE-to-CVE mapping.

## Quick Start

### 1. Install
```bash
go install github.com/saixpereos-debug/parashu@latest
```

### 2. Update Database
Initialize the local vulnerability database (requires internet once):
```bash
parashu db update
```

### 3. Scan
**Quick Scan (Top 1000 ports):**
```bash
parashu scan 192.168.1.10
```

**CIDR Range Scan:**
```bash
parashu scan 10.0.0.0/24 --output html --output-file report.html
```

**Stealth Banner Grab (No CVE lookup):**
```bash
parashu scan 10.0.0.5 --banners-only
```
