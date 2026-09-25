# scanner.py
# Handles network probing, RTT latency measurement, banner grabbing, and dynamic speed estimation

import socket
import time
import statistics
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


def scan_target(target_ip, port, sample_size=10):
    """
    Probes target port multiple times to measure precise RTT statistics (Mean & Std Dev).
    Guarantees mathematically that safe recommended speed is always <= measured speed.
    """
    rtt_list = []
    banner = "No Banner Received"
    is_open = False

    for i in range(sample_size):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(config.CONNECTION_TIMEOUT)

            start_time = time.perf_counter()
            s.connect((target_ip, port))
            end_time = time.perf_counter()

            rtt = end_time - start_time
            rtt_list.append(rtt)
            is_open = True

            # Grab banner on the first successful probe
            if i == 0:
                banner = grab_banner(s, target_ip, port)

            s.close()
            time.sleep(0.05)  # Lightweight interval to prevent socket congestion
        except (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError):
            continue

    # Require at least 2 successful probes for valid statistical analysis
    if not is_open or len(rtt_list) < 2:
        return {
            "is_open": is_open,
            "rtt_ms": None,
            "rtt_std_ms": None,
            "estimated_speed": None,
            "safe_speed_std": None,
            "banner": banner if is_open else "Service Unreachable",
        }

    # Statistical calculation on the exact same dataset
    mean_rtt = sum(rtt_list) / len(rtt_list)
    std_rtt = statistics.stdev(rtt_list)
    overhead = config.HEURISTIC_PROTOCOL_OVERHEAD.get(port, config.DEFAULT_OVERHEAD)

    # 1. Base measured speed based on mean RTT
    base_time = mean_rtt + overhead
    estimated_speed = round(1.0 / base_time, 2) if base_time > 0 else None

    # 2. Dynamic safe speed: mean + std dev margin (Guaranteed <= estimated_speed)
    safe_time = mean_rtt + std_rtt + overhead
    safe_speed_std = round(1.0 / safe_time, 2) if safe_time > 0 else estimated_speed

    return {
        "is_open": True,
        "rtt_ms": round(mean_rtt * 1000, 2),
        "rtt_std_ms": round(std_rtt * 1000, 2),
        "estimated_speed": estimated_speed,
        "safe_speed_std": safe_speed_std,
        "banner": banner,
    }