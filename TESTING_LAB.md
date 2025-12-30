# Parashu Evasion Testing Lab Guide

To test Parashu's advanced evasion features at their "full potential," you need a controlled environment with an active **Intrusion Prevention System (IPS)**. This guide outlines how to set up a real-world testing scenario using **Suricata**.

---

## 🏗️ 1. Lab Setup: The "Red vs. Blue" Environment

The most effective way to test is using **Docker** or **VMs** (e.g., VirtualBox) to simulate a network boundary.

### Recommended Tool: Suricata
Suricata is the industry standard for open-source IPS in 2025. It handles multi-threading and deep packet inspection (DPI) better than classic Snort.

**Setup with Docker:**
```bash
docker run --rm -it --net=host \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  jasonish/suricata:latest
```

---

## 🧪 2. Real-Case Test Scenarios

### Scenario A: Avoiding "Threshold" Alerts (Timing)
Most IPS devices alert when they see more than X connections per second (e.g., 15/sec).

- **The Test**: Scan a target with default settings vs. `-T0` (Paranoid).
- **Parashu Command**:
  ```bash
  parashu scan <target> --T0
  ```
- **IPS Behavior**: Suricata's `threshold` preprocessor will flag the default scan immediately. The `-T0` scan, which delays probes by 5 minutes, will likely stay under the radar of most automated alerts.

### Scenario B: Evasion of Length-Based Signatures
Some IDS rules are triggered by the specific size of a Nmap/Parashu probe packet (usually very small, ~40-60 bytes).

- **The Test**: Use `--data-length` to pad the packet to look like a legitimate payload.
- **Parashu Command**:
  ```bash
  parashu scan <target> --data-length 1200
  ```
- **IPS Behavior**: Rules looking for "Nmap-like tiny packets" will fail because the MTU-filling padding makes the packet look like standard data traffic.

### Scenario C: Stealth Discovery (Ping Suppression)
Firewalls often block or log ICMP (Ping) packets. If you ping first, you've already "knocked" and left a log.

- **The Test**: Normal scan vs. `-n` (No-Ping).
- **Parashu Command**:
  ```bash
  parashu scan <target> -n
  ```
- **IPS Behavior**: By skipping the discovery phase, you avoid triggering "ICMP sweep" alerts. The scanner goes straight to the port, appearing as an isolated (and potentially accidental) connection attempt.

---

## 🔍 3. Advanced Integration: Zeek for Behavioral Analysis

While Suricata uses signatures, **Zeek** (formerly Bro) analyzes *behavior*. 

**The Challenge:**
Zeek doesn't care about packet size; it cares about "Why is this IP touching 500 ports in a logical sequence?".

**How to Beat It:**
Combine **Proxy Routing** with **Randomized Timing**:
```bash
parashu scan <target> --proxies 127.0.0.1:9050 --scan-delay 2s
```
By routing through Tor or a SOCKS5 proxy, the "Behavioral" fingerprint is attributed to the proxy IP, and the slow delay prevents Zeek from linking the connections as a single "Scan Event."

---

## 🚀 4. Summary Table: What to Monitor

| Feature | IPS Counter-Measure | Evasion Success Metric |
| :--- | :--- | :--- |
| **-T0 to -T2** | Rate-limiting / Thresholds | No "Portscan Detected" logs. |
| **--no-ping** | ICMP Filtering / Logs | No "ICMP Echo Request" logs in firewall. |
| **--data-length** | Signature Matching (DPI) | Bypasses `content-length` rules. |
| **--proxies** | IP Blacklisting / Geofencing | Target sees Proxy IP, not yours. |

---

### Pro Tip: Viewing IPS Logs
If using Suricata, monitor the `fast.log` to see if you've been caught:
```bash
tail -f /var/log/suricata/fast.log
```
