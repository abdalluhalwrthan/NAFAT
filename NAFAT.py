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
            return None  # If any IP is invalid, return None
    return ips if ips else None


def get_ports_from_user():
    """Reads comma-separated target ports from CLI, validates range (1-65535), or loops until valid."""
    print("\n[*] Standard Ports: 21 (FTP), 22 (SSH), 23 (Telnet), 80 (HTTP), 443 (HTTPS)")

    while True:
        user_input = input(
            "Enter target ports separated by commas [Press Enter for default (21,22,23,80,443)]: "
        ).strip()

        if not user_input:
            return [21, 22, 23, 80, 443]

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

        print("[-] Invalid port(s) detected. Ports must be numbers between 1 and 65535.")
        print("    Please try again.")


def get_attack_settings():
    """Prompts user to select attack mode and returns configuration parameters."""
    print("\n--- Attack Mode Selection ---")
    print("1) Wordlist Attack (List-based)")
    print("2) Pure Brute-Force (N^L Combination)")

    choice = input("Select attack mode (1/2) [Default: 1]: ").strip()

    if choice != "2":
        path_input = input(
            f"Enter Wordlist path [Press Enter for default '{config.DEFAULT_WORDLIST}']: "
        ).strip()
        wordlist_path = path_input if path_input else config.DEFAULT_WORDLIST
        return {"mode": "Wordlist", "path": wordlist_path}

    print("\n--- Character Sets ---")
    for key, (size, description) in config.CHARSETS.items():
        print(f"{key}) {description} (Size: {size})")

    charset_choice = input("Select character set (1-4) [Default: 2]: ").strip()
    if charset_choice not in config.CHARSETS:
        charset_choice = "2"

    try:
        length_input = int(
            input("Enter password length to evaluate [Default: 6]: ").strip()
        )
        length = length_input if length_input > 0 else 6
    except ValueError:
        length = 6

    return {"mode": "Pure Brute-Force", "charset_key": charset_choice, "length": length}


def main():
    print("=" * 68)
    print("  NETWORK AUTHENTICATION FEASIBILITY ASSESSMENT TOOL (NAFAT)  ")
    print("=" * 68)

    # 1. IP List Validation Loop
    while True:
        ip_input = input("\nEnter Target IP Address(es) separated by commas (e.g., 192.168.1.10, 192.168.1.20): ").strip()
        target_ips = validate_ip_list(ip_input)
        if target_ips:
            break
        print("[-] Invalid IPv4 format detected in one or more entries. Please try again.")

    # 2. Port Selection Loop
    ports = get_ports_from_user()

    # 3. Attack Configuration
    attack_config = get_attack_settings()

    assessment_results = {}

    print("\n[*] Starting Active Scan & Dynamic Rate Feasibility Probing across targets...")

    # 4. Scanning & Calculations Loop (Nested for multiple IPs and ports)
    for target_ip in target_ips:
        for port in ports:
            print(f"[+] Probing {target_ip}:{port}...")
            scan_res = scanner.scan_target(target_ip, port)
            speed = scan_res["estimated_speed"]

            if attack_config["mode"] == "Wordlist":
                tries, used_path = calculator.count_wordlist(attack_config["path"])
                if tries is None:
                    print(
                        f"[-] Error reading wordlist '{used_path}'. Falling back to default."
                    )
                    tries, used_path = calculator.count_wordlist(config.DEFAULT_WORDLIST)
                    if tries is None:
                        print(
                            f"[-] Critical: Could not read default wordlist at '{config.DEFAULT_WORDLIST}'."
                        )
                        tries = 0
                attack_type_str = f"Wordlist ({used_path})"
            else:
                tries, size, description = calculator.calculate_brute_force(
                    attack_config["length"], attack_config["charset_key"]
                )
                attack_type_str = f"Pure Brute-Force ({description}, L={attack_config['length']})"

            calc_res = calculator.calculate_feasibility(tries, speed=speed)

            # Build endpoint dataset for each IP:Port combination
            endpoint_key = f"{target_ip}:{port}"
            assessment_results[endpoint_key] = {
                "is_open": scan_res["is_open"],
                "banner": scan_res["banner"],
                "attack_type": attack_type_str,
                "total_tries": calc_res["total_tries"],
                "speed_per_second": calc_res["speed_per_second"],
                "seconds_needed": calc_res["seconds_needed"],
                "minutes_needed": calc_res["minutes_needed"],
                "hours_needed": calc_res["hours_needed"],
                "days_needed": calc_res["days_needed"],
                "feasible": calc_res["feasible"],
            }

    # 5. Build Report Text & Save Synced Reports (TXT & JSON)
    report_text = report.build_report_text(assessment_results)
    txt_file, json_file = report.save_reports(assessment_results, report_text)

    # 6. Display Results in Terminal
    print("\n" + report_text)
    print(f"\n[+] TXT Report saved successfully: {txt_file}")
    print(f"[+] JSON Data saved successfully: {json_file}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Assessment cancelled by user (Ctrl+C). Exiting safely.")
        sys.exit(0)