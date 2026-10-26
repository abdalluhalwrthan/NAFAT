# config.py
# Configuration settings for Network Authentication Feasibility Assessment Tool (NAFAT v1.2)

import os

# TCP Sampling Settings (explicit measurement configuration, not server capacity limits)
CONNECTION_TIMEOUT = 3.0
PROBE_INTERVAL_SECONDS = 0.05
PROBE_SAMPLE_SIZE = 10
ADAPTIVE_MAX_SAMPLE_SIZE = 20

# Default Synthetic Probe Username (used automatically for service calibration without requiring a real account)
DEFAULT_CALIBRATION_USER = "nafat_probe"

# FTP Active Probe Settings (only used when explicitly authorized and opted-in)
# FTP_AUTH_TIMEOUT is a maximum response wait ceiling for USER/PASS, never a fixed delay added to predictions.
FTP_AUTH_TIMEOUT = 10.0
FTP_MAX_REUSE_PROBES = 5
FTP_PROBE_REJECT_TOKEN = "nafat_calibration_reject_probe"

# SSH Active Probe & Handshake Settings (only used when explicitly authorized and opted-in)
# SSH_HANDSHAKE_TIMEOUT and SSH_AUTH_TIMEOUT are response wait ceilings, never fixed delays added to predictions.
# SSH_MAX_REUSE_PROBES=7 allows probing past OpenSSH's default MaxAuthTries=6 to confirm exact server session reuse limits.
SSH_HANDSHAKE_TIMEOUT = 15.0
SSH_AUTH_TIMEOUT = 30.0
SSH_MAX_REUSE_PROBES = 7
SSH_PROBE_REJECT_TOKEN = "nafat_calibration_reject_probe"


# Minimum number of auth-calibration sessions (T_auth / reconnect-timing samples) to run
# before halting early. Was hardcoded to 2, which is enough to confirm K_srv consistently
# but too small a sample for reconnect-timing statistics when K_eff is low (many reconnects
# expected in the real workload). Raised to 5 for a sturdier T_disc/T_auth distribution while
# remaining a small, non-disruptive number of extra probe connections.
MIN_AUTH_CALIBRATION_SESSIONS = 5

# Default Pre-Assessment Planning Time Budget (in hours) for Network Time-Cost Comparison
DEFAULT_PLANNING_BUDGET_HOURS = 72.0

# Network Variability Classification Thresholds (Coefficient of Variation = SD / Mean)
CV_LOW_THRESHOLD = 0.15       # CV < 15%  -> Low relative variability
CV_MODERATE_THRESHOLD = 0.35  # CV < 35%  -> Moderate relative variability; >= 35% -> High

# Character set definitions for Mode 3 (Exhaustive Search Space Planning)
CHARSETS = {
    "1": (10, "Digits Only (0-9)"),
    "2": (26, "Lowercase Alphabets (a-z)"),
    "3": (62, "Alphanumeric (a-z, A-Z, 0-9)"),
    "4": (95, "Printable ASCII (including space)"),
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WORDLIST = os.path.join(BASE_DIR, "wordlists", "AnyWordList.txt")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
EXAMPLES_DIR = os.path.join(BASE_DIR, "examples")