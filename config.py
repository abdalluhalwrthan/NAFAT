# config.py
# Configuration settings for Network Authentication Feasibility Assessment Tool (NAFAT)
import os
# Fallback speed map (guesses/sec) if RTT fails
SPEED_MAP = {
    21: 20,   # FTP
    22: 10,   # SSH
    23: 15,   # Telnet
    80: 50,   # HTTP
    443: 30,  # HTTPS
}

# Protocol Authentication Overhead (in seconds)
# Added to RTT to estimate real-world brute-force speed
HEURISTIC_PROTOCOL_OVERHEAD ={
    21: 0.03,  # FTP
    22: 0.08,  # SSH 
    23: 0.02,  # Telnet
    80: 0.01,  # HTTP
    443: 0.02, # HTTPS
}


DEFAULT_SPEED = 30 # Fallback rate (guesses/sec) if RTT measurement fails
MAX_HOURS = 72  # Feasibility threshold
CONNECTION_TIMEOUT = 3.0


# Character set definitions for Pure Brute-Force
CHARSETS = {
    "1": (10, "Digits Only (0-9)"),
    "2": (26, "Lowercase Alphabets (a-z)"),
    "3": (62, "Alphanumeric (a-z, A-Z, 0-9)"),
    "4": (95, "Full ASCII (Letters, Digits, Symbols)") # ASCII stands for American Standard Code for Information Interchange
}

# Default Wordlist Configurations
# هذا يحسب المسار بناءً على مكان config.py نفسه
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WORDLIST = os.path.join(BASE_DIR, "wordlists", "Pwdb_top-1000.txt")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")