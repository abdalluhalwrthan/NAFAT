# report.py
# Handles formatting, text generation, and JSON/TXT persistence for NAFAT assessment reports

import json
import os
from datetime import datetime
import config


def build_report_text(data):
    """
    Generates a clean, dual-use security audit text string for console output and file storage.
    Expects data dictionary keyed by target endpoint (e.g. '192.168.1.10:21').
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_lines = [
        "=" * 70,
        "  NETWORK AUTHENTICATION FEASIBILITY ASSESSMENT REPORT (NAFAT)  ",
        "=" * 70,
        f"Generated On : {timestamp}",
        "=" * 70,
    ]

    for endpoint, metrics in data.items():
        is_open = metrics.get("is_open", False)
        banner = metrics.get("banner", "N/A")
        audit_mode = metrics.get("audit_mode", "N/A")

        if is_open:
            status_str = "OPEN (Accessible)"

            feasible_val = metrics.get("feasible")
            if feasible_val is True:
                resilience_str = "HIGH RISK (Low Resilience - Rapid Feasibility)"
            elif feasible_val is False:
                resilience_str = "SECURE / RESILIENT (Long Exposure Window Required)"
            else:
                resilience_str = "DIAGNOSTIC (Baseline Latency Analysis Only)"

            secs = metrics.get("seconds_needed")
            mins = metrics.get("minutes_needed")
            hrs  = metrics.get("hours_needed")
            dys  = metrics.get("days_needed")

            if hrs is not None and hrs >= 1.0:
                time_str = f"{hrs} Hours ({dys} Days)"
            elif mins is not None and mins >= 1.0:
                time_str = f"{mins} Minutes ({hrs} Hours)"
            elif secs is not None:
                time_str = f"{secs} Seconds"
            else:
                time_str = "N/A (Diagnostic Mode)"

            rec_speed = metrics.get("recommended_attack_speed")
            variance_ms = metrics.get("rtt_std_ms", 0)
            rec_speed_str = (
                f"{rec_speed} req/sec  ({variance_ms}ms RTT variance)"
                if rec_speed
                else "N/A"
            )

            total_tries = metrics.get("total_tries")
            tries_str = f"{total_tries:,}" if total_tries is not None else "N/A (Diagnostic)"

            mean_rtt = metrics.get("rtt_ms")
            rtt_display_str = f"{mean_rtt} ms (Jitter: ±{variance_ms} ms)" if mean_rtt is not None else "N/A"

            details_block = [
                f"\n[+] Target Endpoint      : {endpoint}",
                f"    Port Status          : {status_str}",
                f"    Service Banner       : {banner}",
                f"    Latency Baseline     : {rtt_display_str}",
                f"    Audit Mode           : {audit_mode}",
                f"    Evaluated Space      : {tries_str}",
                f"    Throughput Capacity  : {metrics.get('speed_per_second', 0)} req/sec",
                f"    Safe Rate Threshold  : {rec_speed_str}",
                f"    Exposure Duration    : {time_str}",
                f"    Security Resilience  : {resilience_str}",
                "-" * 70,
            ]
        else:
            status_str = "CLOSED / FILTERED"
            details_block = [
                f"\n[+] Target Endpoint      : {endpoint}",
                f"    Port Status          : {status_str}",
                f"    Service Banner       : {banner}",
                f"    Security Status      : SECURE (Endpoint not exposed)",
                "-" * 70,
            ]

        report_lines.extend(details_block)

    report_lines.append("=" * 70)
    return "\n".join(report_lines)


def save_reports(data, report_text):
    """
    Saves assessment results as both formatted TXT and raw JSON files.
    Creates reports directory if missing and returns saved file paths.
    """
    os.makedirs(config.REPORTS_DIR, exist_ok=True)

    filename_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_path  = os.path.join(config.REPORTS_DIR, f"report_{filename_timestamp}.txt")
    json_path = os.path.join(config.REPORTS_DIR, f"report_{filename_timestamp}.json")

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    return txt_path, json_path