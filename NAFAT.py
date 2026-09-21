# NAFAT.py
# Main execution controller for Network Authentication Feasibility Assessment Tool (NAFAT)

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
        except ValueError:
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


def get_attack_settings():
    """Prompts user to select attack mode and returns configuration parameters."""
    print("\n--- Attack Mode ---")
    print("1) Wordlist Attack")
    print("2) Pure Brute-Force (N^L)")

    choice = input("Mode (1/2) [Default: 1]: ").strip()

    if choice != "2":
        path_input = input(f"Wordlist path [Enter for default '{config.DEFAULT_WORDLIST}']: ").strip()
        wordlist_path = path_input if path_input else config.DEFAULT_WORDLIST
        return {"mode": "Wordlist", "path": wordlist_path}

    print("\n--- Character Sets ---")
    for key, (size, description) in config.CHARSETS.items():
        print(f"{key}) {description} (Size: {size})")

    charset_choice = input("Charset (1-4) [Default: 2]: ").strip()
    if charset_choice not in config.CHARSETS:
        charset_choice = "2"

    try:
        length_input = int(input("Password length [Default: 6]: ").strip())
        length = length_input if length_input > 0 else 6
    except ValueError:
        length = 6

    return {"mode": "Pure Brute-Force", "charset_key": charset_choice, "length": length}


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

    
    attack_config = get_attack_settings()

    assessment_results = {}

    print("\n[*] Starting Active Scan & Dynamic Rate Feasibility Probing...")

    
    for target_ip in target_ips:
        for port in ports:
            print(f"[+] Probing {target_ip}:{port}...")
            scan_res = scanner.scan_target(target_ip, port)
            speed = scan_res["estimated_speed"]

            # Skip calculation if port is closed — no RTT to base speed on
            if not scan_res["is_open"]:
                assessment_results[f"{target_ip}:{port}"] = {
                    "is_open": False,
                    "banner": scan_res["banner"],
                    "attack_type": "N/A",
                    "total_tries": None,
                    "speed_per_second": None,
                    "recommended_attack_speed": None,
                    "seconds_needed": None,
                    "minutes_needed": None,
                    "hours_needed": None,
                    "days_needed": None,
                    "feasible": None,
                }
                continue

            # Calculate attack parameters
            if attack_config["mode"] == "Wordlist":
                tries, used_path = calculator.count_wordlist(attack_config["path"])
                if tries is None:
                    print(f"[-] Error reading wordlist '{used_path}'. Falling back to default.")
                    tries, used_path = calculator.count_wordlist(config.DEFAULT_WORDLIST)
                    if tries is None:
                        print(f"[-] Critical: Could not read default wordlist.")
                        tries = 0
                attack_type_str = f"Wordlist ({used_path})"
            else:
                tries, size, description = calculator.calculate_brute_force(attack_config["length"], attack_config["charset_key"])
                attack_type_str = f"Pure Brute-Force ({description}, L={attack_config['length']})"

            calc_res = calculator.calculate_feasibility(tries, speed=speed)

            # Recommended attack speed: slightly below measured speed to stay under IDS threshold
            # Using 85% of measured speed as a safe margin
            recommended_speed = round(speed * 0.85, 2) if speed else None

            assessment_results[f"{target_ip}:{port}"] = {
                "is_open": True,
                "banner": scan_res["banner"],
                "rtt_ms": scan_res["rtt_ms"],
                "attack_type": attack_type_str,
                "total_tries": calc_res["total_tries"],
                "speed_per_second": calc_res["speed_per_second"],
                "recommended_attack_speed": recommended_speed,
                "seconds_needed": calc_res["seconds_needed"],
                "minutes_needed": calc_res["minutes_needed"],
                "hours_needed": calc_res["hours_needed"],
                "days_needed": calc_res["days_needed"],
                "feasible": calc_res["feasible"],
            }

    # 5. Build and Save Reports
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