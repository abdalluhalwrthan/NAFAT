# config.py
# Configuration settings for Network Authentication Feasibility Assessment Tool (NAFAT)

import os

# Protocol Authentication Overhead (in seconds)
# Added to RTT to estimate real-world brute-force speed
HEURISTIC_PROTOCOL_OVERHEAD = {
    21: 0.03,   # FTP
    22: 0.08,   # SSH
    23: 0.02,   # Telnet
    80: 0.01,   # HTTP
    443: 0.02,  # HTTPS
}

# Default overhead for unknown ports
DEFAULT_OVERHEAD = 0.02
MAX_HOURS = 72          # Feasibility threshold
CONNECTION_TIMEOUT = 3.0

# Character set definitions for Pure Brute-Force
CHARSETS = {
    "1": (10,  "Digits Only (0-9)"),
    "2": (26,  "Lowercase Alphabets (a-z)"),
    "3": (62,  "Alphanumeric (a-z, A-Z, 0-9)"),
    "4": (95,  "Full ASCII (Letters, Digits, Symbols)"),
}


BASE_DIR         = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WORDLIST = os.path.join(BASE_DIR, "wordlists", "Pwdb_top-1000.txt")
REPORTS_DIR      = os.path.join(BASE_DIR, "reports")