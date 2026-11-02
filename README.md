# NAFAT — Network Authentication Feasibility Assessment Tool

> *Measure the network first, then decide.* NAFAT estimates **how long** an
> authorized authentication assessment will take, and **what concurrency the
> target can safely tolerate**, *before* the assessment is run — so testing a
> critical service does not accidentally take it down.

NAFAT is a CLI tool that adds a **measurement-to-decision layer** to authorized
security assessment. Instead of guessing at speed or runtime, it **measures the
live service first** — TCP handshake timing, protocol setup overhead, and (when
explicitly authorized) real authentication-rejection timing — and only then
computes a statistically grounded feasibility estimate. No step is based on an
assumed or fixed constant; every number in the output traces back to something
actually measured on the target, or is explicitly marked as an estimate rather
than a validated result.

**NAFAT is a planning and safety layer, not an attack accelerator.** Its purpose
is to keep authorized testing within the server's measured safe limits and to
give both defenders and authorized testers an evidence-based plan — not to speed
up credential guessing.

---

## Dual-Use, Defense-First

NAFAT is designed to serve both sides of an authorized engagement, with
operational safety as the priority:

| Team | Use Case |
|------|----------|
| 🔵 **Blue Team / SOC** | Objective evidence of how long an authentication workload would realistically take against the *current* configuration — a before/after measurement when hardening a setting, and input for detection and rate-limit tuning |
| 🔴 **Red Team (authorized)** | Measured, protocol-aware concurrency and timing guidance, capped at the target's actual observed capacity — so authorized testing stays within safe limits instead of using a guessed or maximal rate |

---

## Core Model

NAFAT does not use a single fixed `RTT + overhead` formula. The feasibility model
is built in layers, each backed by a real measurement, and expressed through a
transparent, reproducible workload model:

```latex
M = \left\lceil \frac{N}{K} \right\rceil
\qquad
T_{full} = M\,(t + h) + (M - 1)\,d + N\,a
```

Where **N** = candidate count, **K** = observed usable attempts per connection,
**M** = modeled connections, **t** = TCP setup, **h** = protocol setup,
**d** = disconnect / reconnect cost, **a** = per-attempt rejection time (means, in
seconds).

The model is assembled from these measured layers:

1. **Adaptive TCP sampling** — multiple connection attempts (default 10, up to 20)
   establish a mean and standard deviation for raw network latency, not a single ping.
2. **Protocol-aware setup timing** — for supported protocols (SSH and FTP), the
   post-TCP handshake/greeting is timed separately from raw TCP latency.
3. **Authorized authentication calibration** *(opt-in only)* — when explicitly
   enabled, NAFAT measures real failed-authentication timing using a synthetic,
   non-guessing probe credential. It never attempts real password guessing.
4. **Server-side connection-reuse detection (K_srv)** — NAFAT empirically
   discovers how many authentication attempts the target actually permits per TCP
   connection (e.g. OpenSSH `MaxAuthTries`), rather than assuming a fixed value.
5. **Conservative rate estimation** — the suggested attempt rate is
   `measured success rate ÷ (mean cycle time + 1 standard deviation)`, so the
   recommendation already accounts for observed timing variability.
6. **Risk-aware concurrency recommendation** — beyond duration, NAFAT recommends a
   safe concurrency level (`-t`) derived from measured timing stability
   (coefficient of variation) and, for SSH, from real constraints like
   cryptographic handshake cost and OpenSSH `MaxStartups`. *This is a risk-aware
   speed suggestion, not a validated optimum.*
7. **Hard physical cap** — the final suggested rate can never exceed the raw TCP
   capacity actually measured against the target.

The result is reported as two distinct estimates, never blended together:

- **Primary Estimate — buffered planning estimate.** The full statistical model
  above; the defensible number to plan against.
- **Secondary Estimate — sample-derived range.** A rough projection from the
  initial timing sample only. Explicitly labeled as unvalidated; **not** a
  confidence interval.

> No fallback or placeholder values. If a quantity was not measured, the field is
> reported as `UNAVAILABLE` with the reason — never a guessed or interpolated number.

---

## Empirical Validation — Live-WAN Proof of Concept

NAFAT was tested on a real wide-area path: a **NAFAT client in Riyadh** against a
**cloud server in Frankfurt, Germany** (1 vCPU / 512 MB RAM), with a measured TCP
connection-establishment time of ~95–108 ms. Across **9 live-WAN scenarios** over
SSH and FTP, the observed runtime of an external execution tool (Hydra) fell
**within NAFAT's pre-execution predicted bounds in all 9/9 cases**:

| Condition | Primary (s) | Secondary (s) | Observed (s) | In range |
|---|---|---|---|---|
| FTP 100 | 86.13–91.64 | 73.24–93.47 | 90.09 | ✓ |
| SSH pre-100 (K=5) | 202.48–241.62 | 132.57–224.96 | 180.85 | ✓ |
| SSH post-100 (K=2) | 240.51–296.49 | 181.52–299.34 | 260.51 | ✓ |
| *(… 6 more scenarios)* | | | | ✓ |

> **Honest scope:** this containment is *descriptive* evidence from a proof of
> concept — it is **not** a validated accuracy guarantee. NAFAT is a working
> prototype; the result shows the measurement-first approach is viable, not that
> every prediction is exact.

---

## Features

- **Adaptive Live RTT Measurement** — real TCP handshake timing via `time.perf_counter`, with automatic resampling for stability
- **Protocol-Aware Overhead Modeling** — SSH and FTP adapters time the post-TCP setup stage separately from raw network latency
- **Authorized Authentication Calibration** — optional, explicitly gated active probing (`--authorize-auth-probes`) that measures real failed-auth timing using a synthetic reject credential; never guesses real passwords
- **Server Reuse-Limit Discovery (K_srv)** — empirically confirms (or lower-bounds) how many auth attempts a server allows per connection
- **SSH Host-Key Verification** — verifies against `known_hosts` by default; unverified keys require a separate, explicit lab opt-in (`--allow-untrusted-host-key`)
- **Risk-Aware Speed & Concurrency Recommendations** — mean + standard-deviation buffering, success-rate discounting, protocol-specific concurrency limits, and a measured hard cap
- **Primary / Secondary Estimate Separation** — the buffered planning estimate is never conflated with the rough early-sample projection
- **Measurement Confidence Scoring** — each assessment is labeled by the quality/size of its underlying sample (`HIGH` / `MODERATE` / `LOW`)
- **Three Operational Modes** — Network Baseline Diagnostic, Dictionary Planning, and Exhaustive Search (keyspace) Planning
- **Service Banner Grabbing** — identifies the running service/version per port where available
- **Multi-Target, Multi-Port Scanning** — probe multiple IPs/hostnames and ports in a single session
- **Time-Budget Planning** — compares the modeled workload time against a configurable network time budget (default 72h) and reports WITHIN/EXCEEDS
- **Tiered, Dual-Format Reporting** — human-readable `.txt` and structured `.json`, both timestamped under `reports/`
- **Interactive CLI and Full argparse CLI** — run guided prompts or script it end-to-end with flags
- **Input Validation & Safe Exit** — IPv4/hostname and port validation, re-prompt loops, clean `Ctrl+C` handling

---

## Project Structure

```
NAFAT/
├── wordlists/
│   └── AnyWordList.txt       # Default wordlist (you can supply any list you want)
├── reports/                  # Auto-created — stores generated .txt/.json reports
├── protocols/
│   ├── __init__.py
│   ├── base.py               # ProtocolAdapter interface shared by all protocol adapters
│   ├── ssh_adapter.py        # SSH handshake timing, host-key verification, auth calibration
│   └── ftp_adapter.py        # FTP greeting timing and auth calibration
├── config.py                 # Sampling, timeout, threshold, and path settings
├── scanner.py                # TCP probing, adaptive RTT sampling, banner grabbing
├── calculator.py             # Statistical feasibility model (rate, concurrency, confidence)
├── report.py                 # Tiered report formatting and TXT/JSON export
├── NAFAT.py                  # CLI entry point (interactive + argparse)
├── __init__.py               # Package metadata (v1.2)
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

> Ports have no default — they must always be specified explicitly.

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

[+] PRIMARY ESTIMATE (buffered planning estimate)
    Mode           : Dictionary Planning
    Workload       : 1,001 candidates
    Attempt Cost   : 3.48 sec/attempt (K=5 attempts/conn, 201 connections)
    Concurrency    : 2 parallel sessions (Hydra: -t 2)  [risk-aware suggestion, not a validated optimum]
    Service Speed  : 28.92 - 34.47 attempts/min (0.48 - 0.57 attempts/sec)
    Full Auth Time : 1742.36s (29.04 minutes) to 2077.04s (34.62 minutes) (K=5, 201 connections)

[+] SECONDARY ESTIMATE (sample-derived range - not statistically validated)
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

- **Live-WAN proof of concept:** Riyadh → cloud server in Frankfurt, Germany (see Empirical Validation above) — 9 scenarios, SSH (22) and FTP (21)
- `scanme.nmap.org` — public test server provided by nmap.org
- Metasploitable2 in an isolated VMware lab environment
- A dedicated (non-shared-resource) SSH server, after VM-local testing showed CPU/virtualization-induced timing noise on long runs

---

## Where NAFAT Fits (vs. existing tools)

NAFAT is a **planning layer**, not a replacement for discovery or execution tools.
As of the last review (October 2026), no single public tool was found combining
all of the following in one framework:

| Capability | NAFAT | nmap | Hydra |
|---|:---:|:---:|:---:|
| Core role | **Plan** (pre-workload) | Discover | Execute |
| Adaptive live RTT measurement (mean + SD) | ✓ | ✗ | ✗ |
| Protocol-specific setup-time modeling | ✓ | ✗ | ✗ |
| Server-side connection-reuse (K) discovery | ✓ | ✗ | ✗ |
| Risk-aware, capped speed/concurrency suggestion | ✓ | ✗ | ✗ |
| Validated vs. unvalidated estimate separation | ✓ | ✗ | ✗ |
| TXT + JSON report | ✓ | ~ | ✗ |

> NAFAT adds a measurement-to-decision layer — it does not replace the scanner or
> the execution tool.

---

## Roadmap

**Already implemented (v1.2):** adaptive RTT calibration, SSH/FTP authentication
timing, server reuse-limit (K_srv) discovery, confidence scoring, explicit
authorization gating, tiered reporting, live-WAN proof of concept.

- **v1.3 (in progress)** — cross-connection rate-limiting / lockout-threshold discovery (Fail2Ban-style, distinct from per-session K_srv); mapping of findings to NCA Essential Cybersecurity Controls (ECC) in the report output
- **v1.5** — before/after configuration-change verification mode; IPv6 support
- **v2.0** — web-protocol (HTTPS) and WAF-behavior modeling; SIEM/SOAR integration for Blue Team rate-limit tuning; HTML reports

---

## Disclaimer

This tool is intended strictly for authorized assessment and educational purposes
only. Do not use it against systems you do not own or do not have explicit written
permission to test. Active authentication calibration is opt-in by design
(`--authorize-auth-probes`) and must only be enabled against authorized targets.