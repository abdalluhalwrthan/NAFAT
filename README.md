# NAFAT — Network Authentication Feasibility Assessment Tool

> *"Is this attack even worth my time?"*

NAFAT is a CLI-based **Dual-Use** security assessment framework for both Red and Blue Teams. It measures live TCP Handshake RTT, applies protocol-specific overhead models, and calculates rate-aware attack speed — enabling pre-attack feasibility decisions before any credential testing begins.

---

## Dual-Use Framework

| Team | Use Case |
|------|----------|
| 🔴 **Red Team** | Rate-aware speed recommendations below IDS detection thresholds |
| 🔵 **Blue Team** | IDS blind-spot identification and defensive gap analysis |

---

## Features

- **Live RTT Measurement** — Measures real TCP Handshake latency via `time.perf_counter`
- **Protocol-Aware Speed Estimation** — `Speed = 1 / (RTT + Protocol Overhead)` per service
- **Recommended Attack Speed** — 85% of measured speed as safe margin below IDS threshold
- **Service Banner Grabbing** — Identifies running service and version per port
- **Multi-Target Scanning** — Probe multiple IPs in a single session
- **Dual Attack Modes** — Wordlist (unique password count) or Pure Brute-Force (N^L keyspace)
- **Smart Time Formatting** — Auto-scales output: Seconds / Minutes / Hours / Days
- **Dual Report Export** — Timestamped `.txt` and `.json` saved under `reports/`
- **Input Validation** — IPv4 format check, port range validation, loop re-prompts
- **Safe Exit Handling** — Ctrl+C exits cleanly without traceback

> No fallback speed values — all speed estimates are derived from live RTT measurement only.  
> If a port is closed, no speed is estimated and the endpoint is marked as unreachable.

---

## Project Structure

```
NAFAT/
├── wordlists/
│   └── Pwdb_top-1000.txt   # Default wordlist (1,000 common passwords)
├── reports/                # Auto-created — stores generated reports
├── config.py               # Protocol overhead constants and path settings
├── scanner.py              # TCP probing, RTT measurement, banner grabbing
├── calculator.py           # Keyspace math and feasibility calculations
├── report.py               # Report formatting and TXT/JSON export
├── NAFAT.py                # Interactive CLI entry point
├── __init__.py             # Package metadata (v1.0.0)
├── README.md
└── requirements.txt
```

---

## Requirements

- Python 3.8+
- No external libraries required

Built-in modules: `socket`, `time`, `json`, `os`, `datetime`, `ipaddress`, `sys`

---

## How to Run

```bash
python NAFAT.py
```

---

## Interactive Prompts

```
Target IP(s): 45.33.32.156

Port(s): 22,80

--- Attack Mode ---
1) Wordlist Attack
2) Pure Brute-Force (N^L)
Mode (1/2) [Default: 1]: 1

Wordlist path [Enter for default '...wordlists/Pwdb_top-1000.txt']:
```

> Ports have no default — the user must specify them explicitly.

---

## Sample Output

```
======================================================================
  NETWORK AUTHENTICATION FEASIBILITY ASSESSMENT REPORT (NAFAT)
======================================================================
Generated On : 2026-09-21 22:59:30
======================================================================

[+] Target Endpoint      : 45.33.32.156:22
    Port Status          : OPEN (Accessible)
    Service Banner       : SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
    Attack Mode          : Wordlist (wordlists/Pwdb_top-1000.txt)
    Total Attempts       : 1,001
    Measured Speed       : 3.37 req/sec
    Recommended Speed    : 2.86 req/sec  (stay at or below this to avoid IDS detection)
    Estimated Time       : 4.95 Minutes (0.08 Hours)
    Feasibility          : YES - (Quick to crack)
----------------------------------------------------------------------

[+] Target Endpoint      : 45.33.32.156:80
    Port Status          : OPEN (Accessible)
    Service Banner       : HTTP/1.1 200 OK
    Attack Mode          : Wordlist (wordlists/Pwdb_top-1000.txt)
    Total Attempts       : 1,001
    Measured Speed       : 4.38 req/sec
    Recommended Speed    : 3.72 req/sec  (stay at or below this to avoid IDS detection)
    Estimated Time       : 3.81 Minutes (0.06 Hours)
    Feasibility          : YES - (Quick to crack)
----------------------------------------------------------------------
======================================================================

[+] TXT Report saved: reports/report_20260921_225930.txt
[+] JSON Report saved: reports/report_20260921_225930.json
```

---

## Report Files

Every run generates two timestamped files under `reports/`:

| File | Format | Purpose |
|------|--------|---------|
| `report_YYYYMMDD_HHMMSS.txt` | Plain Text | Human-readable assessment report |
| `report_YYYYMMDD_HHMMSS.json` | JSON | Structured data for further processing |

---

## Character Sets (Brute-Force Mode)

| Option | Character Set | Size |
|--------|--------------|------|
| 1 | Digits Only (0-9) | 10 |
| 2 | Lowercase Alphabets (a-z) | 26 |
| 3 | Alphanumeric (a-z, A-Z, 0-9) | 62 |
| 4 | Full ASCII (Letters, Digits, Symbols) | 95 |

---

## Tested Against

- `scanme.nmap.org` (45.33.32.156) — public test server provided by nmap.org
- Metasploitable2 in an isolated VMware lab environment
- Tested services: FTP (21), SSH (22), Telnet (23), HTTP (80)

---

## Novelty

No matching tool combining all 8 features was found across GitHub, academic papers, and security-tool databases (September 2026):

| Feature | NAFAT | nmap | Hydra | brtc |
|---------|-------|------|-------|------|
| Live RTT Measurement | ✓ | ✗ | ✗ | ✗ |
| Protocol Overhead Modeling | ✓ | ✗ | ✗ | ✗ |
| Dynamic Speed Estimation | ✓ | ✗ | ✗ | ✗ |
| Feasibility Decision | ✓ | ✗ | ✗ | ~ |
| Banner Grabbing | ✓ | ✓ | ✗ | ✗ |
| Multi-Target Scan | ✓ | ✓ | ✓ | ✗ |
| TXT + JSON Report | ✓ | ~ | ✗ | ✓ |
| Dual-Use Framework | ✓ | ✗ | ✗ | ✗ |

---

## Roadmap

- **v1.5** — Live Speed Calibration, Lockout Detection, argparse CLI, IPv6 Support
- **v2.0** — Dual-Use Rate-Aware Engine + IDS Blind Spot Detector, Risk Scoring, HTML Reports
- **v3.0** — Web Dashboard, REST API, SIEM Integration

---

## Disclaimer

This tool is intended strictly for authorized penetration testing and educational purposes only. Do not use against systems you do not own or have explicit written permission to test.