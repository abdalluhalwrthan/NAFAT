# NAFAT.py
# Main execution controller for Network Authentication Feasibility Assessment Tool (NAFAT)
import socket
import ipaddress
import sys
import calculator
import config
import report
import scanner


def validate_ip_list(ip_input_str):
    """Validates comma-separated IPv4 addresses format."""
    ips = []
    for item in ip_input_str.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            ipaddress.IPv4Address(item)
            ips.append(item)
            continue
        except ValueError:
            pass

        try:
            resolved_ip = socket.gethostbyname(item)
            print(f"[+] '{item}' -> {resolved_ip}")
            ips.append(resolved_ip)
        except socket.gaierror:
            return None

    return ips if ips else None


def get_ports_from_user():
    """Reads comma-separated target ports from CLI and validates range (1-65535)."""
    while True:
        user_input = input("Port(s): ").strip()

        if not user_input:
            print("[-] Port(s) required. Example: 21,22,80")
            continue

        ports = []
        invalid_items = []

        for item in user_input.split(","):
            item = item.strip()
            if item.isdigit() and 1 <= int(item) <= 65535:
                ports.append(int(item))
            else:
                invalid_items.append(item)

        if ports and not invalid_items:
            return ports

        print("[-] Invalid port(s). Must be numbers between 1 and 65535.")


def get_assessment_settings():
    """Prompts user to select security audit profile and returns configuration parameters."""
    print("\n--- Assessment Mode ---")
    print("1) Baseline Network Latency Diagnostic (RTT Probe)")
    print("2) Dictionary Resilience Audit (Wordlist)")
    print("3) Exhaustive Permutation Benchmark (Brute-Force N^L)")

    choice = input("Mode (1/2/3) [Default: 1]: ").strip()

    # 1) RTT Diagnostic Mode (Default)
    if choice == "1" or not choice:
        return {"mode": "RTT_Only"}

    # 2) Wordlist / Dictionary Audit
    if choice == "2":
        path_input = input(f"Wordlist path [Enter for default '{config.DEFAULT_WORDLIST}']: ").strip()
        wordlist_path = path_input if path_input else config.DEFAULT_WORDLIST
        return {"mode": "Dictionary_Audit", "path": wordlist_path}

    # 3) Pure Brute-Force / Permutation Benchmark
    if choice == "3":
        print("\n--- Character Sets ---")
        for key, (size, description) in config.CHARSETS.items():
            print(f"{key}) {description} (Size: {size})")

        charset_choice = input("Charset (1-4) [Default: 2]: ").strip()
        if charset_choice not in config.CHARSETS:
            charset_choice = "2"

        try:
            length_input = int(input("Entropy Length [Default: 6]: ").strip())
            length = length_input if length_input > 0 else 6
        except ValueError:
            length = 6

        return {"mode": "Permutation_Benchmark", "charset_key": charset_choice, "length": length}

    # Fallback default
    return {"mode": "RTT_Only"}


def main():
    print("=" * 68)
    print("  NETWORK AUTHENTICATION FEASIBILITY ASSESSMENT TOOL (NAFAT)  ")
    print("=" * 68)

    # 1. IP Validation
    while True:
        ip_input = input("\nTarget IP(s): ").strip()
        target_ips = validate_ip_list(ip_input)
        if target_ips:
            break
        print("[-] Invalid IPv4 format. Try again.")

    ports = get_ports_from_user()
    assessment_config = get_assessment_settings()

    assessment_results = {}

    print("\n[*] Starting Security Audit & Statistical Latency Analysis...")

    for target_ip in target_ips:
        for port in ports:
            print(f"[+] Auditing {target_ip}:{port} (10 Statistical Samples)...")
            scan_res = scanner.scan_target(target_ip, port, sample_size=10)
            speed = scan_res["estimated_speed"]

            # Skip calculation if port is closed or unreachable
            if not scan_res["is_open"] or speed is None:
                assessment_results[f"{target_ip}:{port}"] = {
                    "is_open": False,
                    "banner": scan_res["banner"],
                    "audit_mode": "N/A",
                    "total_tries": None,
                    "speed_per_second": None,
                    "recommended_attack_speed": None,
                    "rtt_ms": None,
                    "rtt_std_ms": None,
                    "seconds_needed": None,
                    "minutes_needed": None,
                    "hours_needed": None,
                    "days_needed": None,
                    "feasible": None,
                }
                continue

            # Process according to selected dual-use mode
            if assessment_config["mode"] == "RTT_Only":
                audit_type_str = "Network Diagnostic (RTT & Jitter Only)"
                calc_res = {
                    "total_tries": None,
                    "speed_per_second": speed,
                    "seconds_needed": None,
                    "minutes_needed": None,
                    "hours_needed": None,
                    "days_needed": None,
                    "feasible": None,
                }
            elif assessment_config["mode"] == "Dictionary_Audit":
                tries, used_path = calculator.count_wordlist(assessment_config["path"])
                if tries is None:
                    print(f"[-] Error reading dictionary '{used_path}'. Falling back to default.")
                    tries, used_path = calculator.count_wordlist(config.DEFAULT_WORDLIST)
                    if tries is None:
                        print("[-] Critical: Could not read default wordlist.")
                        tries = 0
                audit_type_str = f"Dictionary Audit ({used_path})"
                calc_res = calculator.calculate_feasibility(tries, speed=speed)
            else:
                tries, size, description = calculator.calculate_brute_force(
                    assessment_config["length"], assessment_config["charset_key"]
                )
                audit_type_str = f"Permutation Benchmark ({description}, L={assessment_config['length']})"
                calc_res = calculator.calculate_feasibility(tries, speed=speed)

            assessment_results[f"{target_ip}:{port}"] = {
                "is_open": True,
                "banner": scan_res["banner"],
                "rtt_ms": scan_res["rtt_ms"],
                "rtt_std_ms": scan_res["rtt_std_ms"],
                "audit_mode": audit_type_str,
                "total_tries": calc_res["total_tries"],
                "speed_per_second": calc_res["speed_per_second"],
                "recommended_attack_speed": scan_res["safe_speed_std"],
                "seconds_needed": calc_res["seconds_needed"],
                "minutes_needed": calc_res["minutes_needed"],
                "hours_needed": calc_res["hours_needed"],
                "days_needed": calc_res["days_needed"],
                "feasible": calc_res["feasible"],
            }

    # Build and Save Reports
    report_text = report.build_report_text(assessment_results)
    txt_file, json_file = report.save_reports(assessment_results, report_text)

    print("\n" + report_text)
    print(f"\n[+] TXT Report saved: {txt_file}")
    print(f"[+] JSON Report saved: {json_file}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Assessment cancelled by user (Ctrl+C). Exiting safely.")
        sys.exit(0)