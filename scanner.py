# scanner.py
# Handles network probing, RTT latency measurement, banner grabbing, and dynamic speed estimation

import socket
import time
import config


def grab_banner(s, target_ip, port):
    """Attempts to retrieve raw service banner from an active socket connection."""
    try:
        if port in [80, 443]:
            request = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
            s.send(request.encode())

        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        banner = banner.split("\n")[0].strip()
        return banner if banner else "No Banner Received"
    except Exception:
        return "Banner Grab Timeout/Failed"


def scan_target(target_ip, port):
    """
    Probes target port, measures TCP handshake RTT, calculates dynamic guess speed
    using heuristic protocol overheads, and extracts the service banner.

    Returns estimated_speed = None if port is closed (no RTT measured).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(config.CONNECTION_TIMEOUT)

        # Measure TCP Handshake RTT precisely
        start_time = time.perf_counter()
        s.connect((target_ip, port))
        end_time = time.perf_counter()

        rtt = end_time - start_time  # RTT in seconds

        # Calculate dynamic speed: 1 / (RTT + Protocol Overhead)
        overhead = config.HEURISTIC_PROTOCOL_OVERHEAD.get(port, config.DEFAULT_OVERHEAD)
        total_time_per_request = rtt + overhead

        # Prevents ZeroDivisionError
        if total_time_per_request > 0:
            estimated_speed = round(1.0 / total_time_per_request, 2)
        else:
            estimated_speed = None

        # Retrieve banner before closing socket
        banner = grab_banner(s, target_ip, port)
        s.close()

        return {
            "is_open": True,
            "rtt_ms": round(rtt * 1000, 2),
            "estimated_speed": estimated_speed,
            "banner": banner,
        }

    except (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError):
        # Port is closed or unreachable — no speed can be estimated
        return {
            "is_open": False,
            "rtt_ms": None,
            "estimated_speed": None,
            "banner": "Service Unreachable",
        }