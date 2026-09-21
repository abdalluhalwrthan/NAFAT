# report.py
# Handles formatting, text generation, and JSON/TXT persistence for NAFAT assessment reports

import json
import os
from datetime import datetime
import config


def build_report_text(data):
    """
    Generates a clean, formatted text string for console output and file storage.
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
        attack_mode = metrics.get("attack_type", "N/A")

        if is_open:
            status_str = "OPEN (Accessible)"

            feasibility_str = (
                "YES - (Quick to crack)"
                if metrics.get("feasible")
                else "NO - (Takes too long to crack)"
            )

            # Smart time formatting: Seconds -> Minutes -> Hours
            secs = metrics.get("seconds_needed", 0)
            mins = metrics.get("minutes_needed", 0)
            hrs  = metrics.get("hours_needed", 0)
            dys  = metrics.get("days_needed", 0)

            if hrs >= 1.0:
                time_str = f"{hrs} Hours ({dys} Days)"
            elif mins >= 1.0:
                time_str = f"{mins} Minutes ({hrs} Hours)"
            else:
                time_str = f"{secs} Seconds"

            # Recommended attack speed (85% of measured speed — stays below IDS detection)
            rec_speed = metrics.get("recommended_attack_speed")
            rec_speed_str = (
                f"{rec_speed} req/sec  (stay at or below this to avoid IDS detection)"
                if rec_speed
                else "N/A"
            )

            details_block = [
                f"\n[+] Target Endpoint      : {endpoint}",
                f"    Port Status          : {status_str}",
                f"    Service Banner       : {banner}",
                f"    Attack Mode          : {attack_mode}",
                f"    Total Attempts       : {metrics.get('total_tries', 0):,}",
                f"    Measured Speed       : {metrics.get('speed_per_second', 0)} req/sec",
                f"    Recommended Speed    : {rec_speed_str}",
                f"    Estimated Time       : {time_str}",
                f"    Feasibility          : {feasibility_str}",
                "-" * 70,
            ]
        else:
            status_str = "CLOSED / UNREACHABLE"
            details_block = [
                f"\n[+] Target Endpoint      : {endpoint}",
                f"    Port Status          : {status_str}",
                f"    Service Banner       : {banner}",
                f"    Security Status      : SECURE (Port is closed, no exposure)",
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