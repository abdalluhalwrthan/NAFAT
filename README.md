# NAFAT — Network Authentication Feasibility Framework

> *"A Dual-Use Network Authentication Feasibility Framework for Red Teaming and Defensive Security Optimization"*

NAFAT is a high-precision, CLI-based assessment framework designed to bridge the pre-assessment auditing gap in network security. By conducting live statistical latency sampling via `time.perf_counter` and integrating protocol overhead heuristics, NAFAT quantitatively models network throughput capacity and projects assessment timelines prior to execution. This enables data-driven decision-making, answering *"Is this assessment worth attempting?"* while eliminating unnecessary network noise and resource exhaustion.

---

## Dual-Use Architecture

| Operational Role | Strategic Value & Use Case |
| :--- | :--- |
| 🔴 **Red Team / Offensive Audit** | Establishes empirical, rate-aware audit throughput constrained within natural latency jitter to prevent denial-of-service and uncalibrated traffic bursts. |
| 🔵 **Blue Team / Defensive Optimization** | Identifies authentication exposure windows, quantifies baseline service resilience against automated credential testing, and validates detection telemetry. |

---

## Core Capabilities

- **High-Precision Latency Sampling** — Leverages sub-millisecond socket timing (`time.perf_counter`) over non-congestive handshakes to calculate mean latency (μ_rtt) and statistical jitter (σ_rtt).
- **Protocol Overhead Modeling** — Applies empirical heuristics for upper-layer protocol latency (e.g., SSH key negotiation, HTTP request headers).
- **Statistical Rate Calibration** — Dynamically formulates baseline throughput using variance modeling:
  `Throughput = 1 / (μ_rtt + σ_rtt + Protocol_Overhead)`
  Derives a deterministic **Safe Rate Threshold** strictly within the empirical network variance window.
- **Exposure Window & Resilience Scoring** — Projects complete keyspace/wordlist audit duration against operational SLAs to classify security resilience (e.g., `HIGH RISK` vs `SECURE / RESILIENT`).
- **Tri-Mode Assessment Profiles** — Supports Baseline Latency Diagnostics (RTT only), Dictionary Resilience Audits (Wordlists), and Exhaustive Permutation Benchmarks (N^L).
- **Smart Target Resolution** — Automatically resolves hostnames to IPv4, validates IP formats, and accepts comma-separated multi-target / multi-port execution.
- **Service Banner Verification** — Actively probes target endpoints (including `HEAD` requests for HTTP/HTTPS) to extract operational service banners.
- **Auditable Telemetry Export** — Automatically generates structured timestamped assessment logs in plain text (`.txt`) and machine-readable (`.json`).

---

## Project Structure

```text
NAFAT/
├── wordlists/
│   └── AnyWordList.txt      # Target evaluation wordlist 
├── reports/                 # Auto-generated audit telemetry (TXT & JSON)
├── config.py                # Protocol overhead constants and baseline parameters
├── scanner.py               # Socket probing, banner retrieval, and latency sampling
├── calculator.py            # Statistical latency modeling and timeline projections
├── report.py                # Telemetry structuring and multi-format exporters
├── NAFAT.py                 # Interactive CLI assessment interface
├── __init__.py              # Framework package metadata
├── README.md
└── requirements.txt
```

---

## Requirements

- Python 3.8+
- Zero external dependencies (Uses native standard libraries for maximum portability)

Standard modules: `socket`, `time`, `json`, `os`, `datetime`, `ipaddress`, `sys`, `statistics`

---

## Usage

Run the framework CLI:

```bash
python NAFAT.py
```

### Interactive Assessment Setup

```text
====================================================================
  NETWORK AUTHENTICATION FEASIBILITY ASSESSMENT TOOL (NAFAT)  
====================================================================

Target IP(s): 45.33.32.156, scanme.nmap.org
Port(s): 22,80

--- Assessment Mode ---
1) Baseline Network Latency Diagnostic (RTT Probe)
2) Dictionary Resilience Audit (Wordlist)
3) Exhaustive Permutation Benchmark (Brute-Force N^L)
Mode (1/2/3) [Default: 1]: 2

Wordlist path [Enter for default 'wordlists/AnyWordList.txt']:
```

---

## Sample Telemetry Output

Below is an empirical assessment executed against a public reference target:

```text
[*] Starting Security Audit & Statistical Latency Analysis...
[+] Auditing 45.33.32.156:80 (10 Statistical Samples)...

======================================================================
  NETWORK AUTHENTICATION FEASIBILITY ASSESSMENT REPORT (NAFAT)  
======================================================================
Generated On : 2026-09-25 23:04:48
======================================================================

[+] Target Endpoint      : 45.33.32.156:80
    Port Status          : OPEN (Accessible)
    Service Banner       : HTTP/1.1 200 OK
    Latency Baseline     : 257.7 ms (Jitter: ±49.95 ms)
    Audit Mode           : Dictionary Audit (wordlists/AnyWordList.txt)
    Evaluated Space      : 1,001
    Throughput Capacity  : 3.72 req/sec
    Safe Rate Threshold  : 3.58 req/sec  (49.95ms RTT variance)
    Exposure Duration    : 4.48 Minutes (0.07 Hours)
    Security Resilience  : HIGH RISK (Low Resilience - Rapid Feasibility)
----------------------------------------------------------------------
======================================================================

[+] TXT Report saved: reports/report_20260925_230448.txt
[+] JSON Report saved: reports/report_20260925_230448.json
```

---

## Telemetry Artifacts

Every assessment run exports two audit artifacts under `reports/`:

| Artifact | Type | Role |
| :--- | :--- | :--- |
| `report_YYYYMMDD_HHMMSS.txt` | Formatted Plaintext | Executive summary and human-readable audit findings. |
| `report_YYYYMMDD_HHMMSS.json` | Structured JSON | Machine-readable telemetry for SIEM ingestion and automated parsing. |

---

## Feature Comparison Matrix

No prior tool combining all pre-assessment feasibility capabilities was identified across academic literature or standard tool repositories (September 2026):

| Capability / Feature | NAFAT | Nmap | Hydra | brtc |
| :--- | :---: | :---: | :---: | :---: |
| **Live RTT Measurement** | **✓** | ✗ | ✗ | ✗ |
| **Protocol Overhead Modeling** | **✓** | ✗ | ✗ | ✗ |
| **Dynamic Speed Estimation** | **✓** | ✗ | ✗ | ✗ |
| **Feasibility Decision Logic** | **✓** | ✗ | ✗ | ~ |
| **Banner Grabbing** | **✓** | ✓ | ✗ | ✗ |
| **Multi-Target Scanning** | **✓** | ✓ | ✓ | ✗ |
| **Multi-Format Export (TXT + JSON)** | **✓** | ~ | ✗ | ✓ |
| **Dual-Use Operational Framework** | **✓** | ✗ | ✗ | ✗ |

---

## Engineering Roadmap

- **v1.5 [Q1 2027]** — Live Speed Calibration, Lockout Detection Engine & IPv6 Support.
- **v2.0 [Q2 2027]** — Dual-Use Rate-Aware Engine, IDS Blind Spot Detector & HTML Reporting.
- **v3.0 [Q4 2027]** — Web Dashboard, REST API & Direct SIEM Integration.

---

## Disclaimer

This framework is developed and released strictly for authorized defensive auditing, authorized penetration testing, and academic research. All assessments must be conducted with explicit, written authorization from asset owners.
