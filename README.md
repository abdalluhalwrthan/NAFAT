# NAFAT — Network Authentication Feasibility Assessment Tool

> *"Is this attack even worth my time — and does your defense actually stop it?"*

NAFAT is a CLI-based **Dual-Use** network security assessment framework for both Red and Blue Teams. Instead of guessing at attack speed or defense readiness, it **measures the live network first** — TCP handshake timing, protocol setup overhead, and (when explicitly authorized) real authentication-rejection timing — and only then computes a statistically grounded feasibility estimate. No step is based on an assumed or fixed constant; every number in the output traces back to something actually measured on the target, or is explicitly marked as an estimate rather than a validated result.

---

## Dual-Use Framework

| Team | Use Case |
|------|----------|
| 🔴 **Red Team** | Measured, protocol-aware speed and timing recommendations, capped at the target's actual observed capacity (never a guessed or maximal rate) |
| 🔵 **Blue Team** | Objective evidence of how long an authentication workload would realistically take against the *current* configuration — usable as a before/after measurement when hardening a setting |

---

## Core Model

NAFAT does not use a single fixed `RTT + overhead` formula. The feasibility model is built in layers, each backed by a real measurement:

1. **Adaptive TCP sampling** — multiple connection attempts (configurable, default 10, up to 20) establish a mean and standard deviation for raw network latency, not a single ping.
2. **Protocol-aware setup timing** — for supported protocols (currently SSH and FTP), the post-TCP handshake/greeting is timed separately from raw TCP latency.
3. **Authorized authentication calibration** *(opt-in only)* — when explicitly enabled, NAFAT measures real failed-authentication timing against the target using a synthetic, non-guessing probe credential. It never attempts real password guessing as part of measurement.
4. **Server-side connection reuse detection (K_srv)** — NAFAT empirically discovers how many authentication attempts the target server actually permits per TCP connection (e.g. OpenSSH `MaxAuthTries`), rather than assuming a fixed value.
5. **Conservative rate estimation** — the suggested attempt rate is `measured success rate ÷ (mean cycle time + 1 standard deviation)`, so the recommendation already accounts for observed timing variability instead of just the best case.
6. **Protocol-aware concurrency** — the number of recommended parallel sessions is derived from measured timing stability (coefficient of variation) and, for SSH, from real constraints like cryptographic handshake cost and OpenSSH `MaxStartups`.
7. **Hard physical cap** — the final suggested rate can never exceed the raw TCP capacity actually measured against the target.

The result is reported as two distinct estimates, never blended together:

- **Primary Estimate** — the full statistical model above; this is the validated, defensible number.
- **Secondary Estimate** — a rough projection extrapolated from the initial timing sample only. It is explicitly labeled as unvalidated and is never presented as a confidence interval.

> No fallback or placeholder values. If a quantity was not measured, the field is reported as `UNAVAILABLE` with the reason — never a guessed or interpolated number.

---

## Features

- **Adaptive Live RTT Measurement** — real TCP handshake timing via `time.perf_counter`, with automatic resampling for stability
- **Protocol-Aware Overhead Modeling** — SSH and FTP adapters time the post-TCP setup stage separately from raw network latency
- **Authorized Authentication Calibration** — optional, explicitly gated active probing (`--authorize-auth-probes`) that measures real failed-auth timing using a synthetic reject credential; never guesses real passwords
- **Server Reuse-Limit Discovery (K_srv)** — empirically confirms (or lower-bounds) how many auth attempts a server allows per connection
- **SSH Host-Key Verification** — verifies against `known_hosts` by default; unverified keys require a separate, explicit lab opt-in (`--allow-untrusted-host-key`)
- **Statistically Grounded Speed & Concurrency Recommendations** — mean + standard-deviation buffering, success-rate discounting, and protocol-specific concurrency limits
- **Primary / Secondary Estimate Separation** — the validated full model is never conflated with the rough early-sample projection
- **Measurement Confidence Scoring** — each assessment is labeled by the quality/size of its underlying sample (e.g. `HIGH` / `MODERATE` / `LOW`)
- **Three Operational Modes** — Network Baseline Diagnostic, Dictionary Planning, and Exhaustive Search (brute-force keyspace) Planning
- **Service Banner Grabbing** — identifies the running service/version per port where available
- **Multi-Target, Multi-Port Scanning** — probe multiple IPs/hostnames and ports in a single session
- **Time-Budget Planning** — compares the modeled workload time against a configurable network time budget (default 72h) and reports WITHIN/EXCEEDS
- **Tiered, Dual-Format Reporting** — human-readable `.txt` (Summary → Primary Estimate → Secondary Estimate → Network Conditions → Assumptions & Limitations) and structured `.json`, both timestamped under `reports/`
- **Interactive CLI and Full argparse CLI** — run guided prompts or script it end-to-end with flags
- **Input Validation** — IPv4/hostname validation, port range validation, re-prompt loops
- **Safe Exit Handling** — clean `Ctrl+C` exit, no traceback spam

---

## Project Structure

```
NAFAT/
├── wordlists/
│   └── AnyWordList.txt      # Default wordlist (you can supply any list you want)
├── reports/                 # Auto-created — stores generated .txt/.json reports
├── protocols/
│   ├── __init__.py
│   ├── base.py               # ProtocolAdapter interface shared by all protocol adapters
│   ├── ssh_adapter.py        # SSH handshake timing, host-key verification, auth calibration
│   └── ftp_adapter.py        # FTP greeting timing and auth calibration
├── config.py                 # Sampling, timeout, threshold, and path settings
├── scanner.py                 # TCP probing, adaptive RTT sampling, banner grabbing
├── calculator.py              # Statistical feasibility model (rate, concurrency, confidence)
├── report.py                  # Tiered report formatting and TXT/JSON export
├── NAFAT.py                   # CLI entry point (interactive + argparse)
├── __init__.py                 # Package metadata (v1.2)
├── README.md
└── requirements.txt
```

---

## Requirements

- Python 3.8+
- No hard external dependencies for TCP/FTP measurement

Built-in modules used: `socket`, `time`, `json`, `os`, `datetime`, `ipaddress`, `sys`, `math`, `statistics`, `errno`, `hashlib`, `logging`, `argparse`

**Optional:** `paramiko` — if installed, NAFAT uses it to parse certain SSH protocol messages more robustly during authentication calibration. If it is not installed, SSH timing and calibration still work; NAFAT falls back to its own minimal message parsing.

---

## How to Run

### Interactive mode
```bash
python NAFAT.py
```
```
--- Assessment Mode ---
1) Network Baseline Diagnostic (TCP Connection Establishment)
2) Dictionary Audit Planning (Wordlist / Candidate Count)
3) Exhaustive Search Space Planning (Brute-Force N^L)
```

### CLI mode (scriptable)
```bash
python NAFAT.py --target 45.33.32.156 --port 22 --mode 2 \
  --wordlist wordlists/AnyWordList.txt \
  --authorize-auth-probes --ssh-user nafat_probe
```

Key flags:

| Flag | Purpose |
|---|---|
| `--target / -t` | Comma-separated IPv4 address(es) or hostname(s) |
| `--port / -p` | Comma-separated target port(s) |
| `--mode / -m` | `1` Baseline, `2` Dictionary Planning, `3` Exhaustive Search Planning |
| `--wordlist / -w`, `--candidates / -c` | Mode 2 input |
| `--charset`, `--length / -l` | Mode 3 keyspace definition |
| `--samples`, `--pacing-ms` | TCP sampling size and inter-attempt pacing |
| `--measure-protocol`, `--protocol` | Enable/choose protocol-specific setup timing |
| `--authorize-auth-probes` | **Required** to enable any active authentication calibration (state-changing; off by default) |
| `--ssh-user`, `--ftp-user`, `--auth-user` | Synthetic calibration username (defaults to a non-guessing probe account) |
| `--known-hosts`, `--allow-untrusted-host-key` | SSH host-key verification controls |
| `--budget-hours` | Network planning time budget used for the WITHIN/EXCEEDS verdict |

Run `python NAFAT.py --help` for the complete list.

> Ports have no default — they must always be specified explicitly, in both modes.

---

## Authorization Model

Active authentication calibration (the only part of NAFAT that sends real authentication attempts, always using a synthetic non-guessing credential) is **off by default** and requires the operator to explicitly opt in:

- In CLI mode, `--authorize-auth-probes` must be passed explicitly before any calibration probe is sent.
- SSH host-key trust is gated separately: by default an unverified host key is rejected; `--allow-untrusted-host-key` is a distinct, explicit opt-in intended for isolated lab targets only.
- Calibration never attempts real credential guessing — it measures the server's *rejection* timing using a fixed synthetic token, so no password list is ever used during measurement itself.

NAFAT is built to be run only against systems the operator owns or has explicit written authorization to test — see Disclaimer below.

---

## Sample Output (`.txt` report)

```
================================================================
             NAFAT | NETWORK ASSESSMENT REPORT
================================================================
Generated On       : 2026-10-21 19:52:17

[+] TARGET
    Endpoint       : 192.168.1.50:22
    Service        : SSH
    Status         : OPEN
    Protocol       : SSH

[+] SUMMARY
    Trusted Estimate : 1742.36s (29.04 minutes) to 2077.04s (34.62 minutes)
    Confidence       : MODERATE
    Planning         : WITHIN 72h NETWORK BUDGET

[+] PRIMARY ESTIMATE
    Mode           : Dictionary Planning
    Workload       : 1,001 candidates
    Attempt Cost   : 3.48 sec/attempt (K=5 attempts/conn, 201 connections)
    Concurrency    : 2 parallel sessions (Hydra: -t 2)
    Service Speed  : 28.92 - 34.47 attempts/min (0.48 - 0.57 attempts/sec)
    Full Auth Time : 1742.36s (29.04 minutes) to 2077.04s (34.62 minutes) (K=5, 201 connections)

[+] SECONDARY ESTIMATE (early-sample projection - not statistically validated)
    Sample Range   : 1145.73s (19.10 minutes) to 1936.46s (32.27 minutes)
    Note           : Derived by scaling the min/max of the initial timing sample.
                     This is not a confidence interval - treat the Primary Estimate
                     above as the number to plan against.

[+] NETWORK CONDITIONS
    TCP Latency    : 45.20 ms
    Protocol Setup : 312.40 ms (SSH Handshake)
    Host Key       : VERIFIED (known_hosts)
    Failed Auth    : 180.50 ms (SSH userauth; 48/48 probes)
    Server Reuse   : 5 attempts/conn (Confirmed Limit)
    Variability    : LOW (CV: 8.20%)

[+] ASSUMPTIONS & LIMITATIONS
    - Assumes the auditing client reuses each SSH connection up to the
      server-enforced limit (K_srv=5).

----------------------------------------------------------------
Note: Includes measured TCP latency, protocol greeting overhead,
and authorized SSH failed-authentication timing.
================================================================

[+] TXT Report saved: reports/report_2026-10-21_195217.txt
[+] JSON Report saved: reports/report_2026-10-21_195217.json
```

---

## Report Files

Every run generates two timestamped files under `reports/`:

| File | Format | Purpose |
|------|--------|---------|
| `report_<timestamp>.txt` | Plain Text | Tiered, human-readable assessment report |
| `report_<timestamp>.json` | JSON | Full structured data, including every underlying measurement, for further processing |

---

## Character Sets (Mode 3 — Exhaustive Search Planning)

| Option | Character Set | Size |
|--------|--------------|------|
| 1 | Digits Only (0-9) | 10 |
| 2 | Lowercase Alphabets (a-z) | 26 |
| 3 | Alphanumeric (a-z, A-Z, 0-9) | 62 |
| 4 | Printable ASCII (incl. space) | 95 |

---

## Tested Against

- `scanme.nmap.org` — public test server provided by nmap.org
- Metasploitable2 in an isolated VMware lab environment
- A dedicated (non-shared-resource) SSH server, after VM-local testing showed CPU/virtualization-induced timing noise on long runs
- Tested services: FTP (21), SSH (22)

---

## Novelty

As of the last review (October 2026), no single public tool was found combining all of the following in one framework:

| Feature | NAFAT | nmap | Hydra | brtc |
|---------|-------|------|-------|------|
| Adaptive live RTT measurement (mean + SD, not single ping) | ✓ | ✗ | ✗ | ✗ |
| Protocol-specific setup-time modeling | ✓ | ✗ | ✗ | ✗ |
| Server-side connection-reuse limit discovery | ✓ | ✗ | ✗ | ✗ |
| Statistically buffered, capped speed recommendation | ✓ | ✗ | ✗ | ✗ |
| Validated vs. unvalidated estimate separation | ✓ | ✗ | ✗ | ✗ |
| Banner Grabbing | ✓ | ✓ | ✗ | ✗ |
| Multi-Target Scan | ✓ | ✓ | ✓ | ✗ |
| TXT + JSON Report | ✓ | ~ | ✗ | ✓ |
| Dual-Use (Red + Blue) framing | ✓ | ✗ | ✗ | ✗ |

---

## Roadmap

**Already implemented (v1.2):** adaptive RTT calibration, SSH/FTP authentication timing, server reuse-limit (K_srv) discovery, confidence scoring, explicit authorization gating, tiered reporting.

- **v1.3 (in progress)** — Rate-Limiting Threshold Discovery (cross-connection, Fail2Ban-style detection — distinct from the existing per-session K_srv), direct mapping of findings to NCA Essential Cybersecurity Controls (ECC) in the report output
- **v1.5** — Before/after configuration-change verification mode, IPv6 support
- **v2.0** — IDS/IDS-readiness blind-spot detector, risk scoring, HTML reports
- **v3.0** — Web dashboard, REST API, SIEM integration

---

## Disclaimer

This tool is intended strictly for authorized penetration testing and educational purposes only. Do not use against systems you do not own or do not have explicit written permission to test. Active authentication calibration is opt-in by design (`--authorize-auth-probes`) and must only be enabled against authorized targets.