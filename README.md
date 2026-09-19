# NAFAT - Network Authentication Feasibility Assessment Tool

## Overview
NAFAT is an interactive CLI-based security assessment tool designed for penetration testers and network security analysts. It evaluates the feasibility and time required for wordlist and brute-force attacks against target services. By measuring network latency (RTT) via TCP sockets and integrating protocol overheads, NAFAT provides dynamic time estimates and generates structured report files.

---

## Features

- **Multi-Target Scanning:** Probe multiple IP addresses in a single session
- **Multi-Port Probing:** Scan multiple ports simultaneously with comma-separated input
- **Live RTT Measurement:** Measures real TCP Handshake latency for dynamic speed estimation
- **Protocol-Aware Speed Estimation:** Adjusts guessing rate based on protocol overhead (SSH, FTP, HTTP...)
- **Service Banner Grabbing:** Retrieves raw service banners to identify running services
- **Dual Attack Modes:**
  - Wordlist Attack — estimates time based on unique password count
  - Pure Brute-Force — calculates full search space using character set complexity (N^L)
- **Smart Time Formatting:** Displays time in Seconds / Minutes / Hours automatically based on scale
- **Dual Report Export:** Saves results as both `.txt` and `.json` under `reports/`
- **Input Validation:** Validates IPv4 format and port ranges with loop re-prompts
- **Safe Exit Handling:** Ctrl+C exits cleanly without traceback

---

## Project Structure

```
NAFAT/
├── wordlists/
│   └── Pwdb_top-1000.txt       # Default wordlist (1,000 common passwords)
├── reports/                    # Auto-created — stores generated reports
├── config.py                   # Centralized constants and protocol settings
├── scanner.py                  # Socket probing, RTT measurement, banner grabbing
├── calculator.py               # Password space math and feasibility calculations
├── report.py                   # Report formatting and file export (TXT + JSON)
├── NAFAT.py                     # Interactive CLI entry point
├── README.md
└── requirements.txt
```

---

## Requirements

- Python 3.8+
- No external libraries required

Built-in modules used: `socket`, `time`, `json`, `os`, `datetime`, `ipaddress`, `sys`

---

## How to Run

```bash
python NAFAT.py
```

---

## Interactive Prompts

```
Enter Target IP Address(es) separated by commas: 192.168.1.10, 192.168.1.20

Enter target ports separated by commas [Press Enter for default (21,22,23,80,443)]: 21,22,80

--- Attack Mode Selection ---
1) Wordlist Attack (List-based)
2) Pure Brute-Force (N^L Combination)
Select attack mode (1/2) [Default: 1]: 1

Enter Wordlist path [Press Enter for default]: 
```

---

## Sample Output

```
======================================================================
  NETWORK AUTHENTICATION FEASIBILITY ASSESSMENT REPORT (NAFAT)
======================================================================
Generated On : 2026-09-17 03:53:39
======================================================================

[+] Target Endpoint : 192.168.1.10:21
    Port Status     : OPEN (Accessible)
    Service Banner  : 220 (vsFTPd 2.3.4)
    Attack Mode     : Wordlist (wordlists/Pwdb_top-1000.txt)
    Total Attempts  : 1,001
    Speed Rate      : 24.06 req/sec
    Estimated Time  : 41.6 Seconds
    Feasibility     : YES - (Quick to crack)
----------------------------------------------------------------------

[+] Target Endpoint : 192.168.1.10:22
    Port Status     : OPEN (Accessible)
    Service Banner  : SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
    Attack Mode     : Wordlist (wordlists/Pwdb_top-1000.txt)
    Total Attempts  : 1,001
    Speed Rate      : 12.41 req/sec
    Estimated Time  : 1.34 Minutes (0.02 Hours)
    Feasibility     : YES - (Quick to crack)
----------------------------------------------------------------------

[+] Target Endpoint : 192.168.1.10:443
    Port Status     : CLOSED / UNREACHABLE
    Service Banner  : Service Unreachable
    Security Status : SECURE (Port is closed, no exposure)
----------------------------------------------------------------------
======================================================================

[+] TXT Report saved: reports/report_20260917_035339.txt
[+] JSON Report saved: reports/report_20260917_035339.json
```

---

## Report Files

Every run automatically generates two files inside `reports/`:

| File | Format | Purpose |
|------|--------|---------|
| `report_YYYYMMDD_HHMMSS.txt` | Plain Text | Human-readable, ready to attach to assessments |
| `report_YYYYMMDD_HHMMSS.json` | JSON | Structured data for further processing or integration |

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

- Metasploitable2 in an isolated local VM environment
- Tested services: FTP (21), SSH (22), Telnet (23), HTTP (80)

---

## Disclaimer

This tool is intended strictly for authorized penetration testing and educational purposes only. Do not use against systems you do not own or have explicit written permission to test.