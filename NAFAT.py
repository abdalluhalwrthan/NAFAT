# NAFAT.py
# Main execution controller for Network Authentication Feasibility Assessment Tool (NAFAT v1.2)

import argparse
import ipaddress
import math
import socket
import sys

import calculator
import config
import report
import scanner
import protocols
from protocols import ssh_adapter


def validate_ip_list(ip_input_str, resolve_hostnames=True):
    """Validate comma-separated IPv4 addresses or resolve hostnames to IPv4 addresses."""
    if not isinstance(ip_input_str, str):
        return None
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

        if not resolve_hostnames:
            return None

        try:
            resolved_ip = socket.gethostbyname(item)
            print(f"[+] '{item}' -> {resolved_ip}")
            ips.append(resolved_ip)
        except (socket.gaierror, OSError):
            return None

    return ips if ips else None


def parse_ports_string(user_input):
    """Parse and validate a comma-separated port string (1-65535)."""
    if not isinstance(user_input, str) or not user_input.strip():
        return None
    ports = []
    for item in user_input.split(","):
        item = item.strip()
        if item.isdigit() and 1 <= int(item) <= 65535:
            ports.append(int(item))
        else:
            return None
    return ports if ports else None


def _safe_input(prompt):
    """Read a line from stdin safely, returning empty string on EOFError or exhausted input."""
    try:
        return input(prompt)
    except (EOFError, StopIteration, OSError):
        return ""


def _required_input(prompt):
    """Abort before assessment when a required interactive prompt cannot be read."""
    try:
        return input(prompt)
    except (EOFError, StopIteration, OSError):
        print("\n[-] Interactive input unavailable. Exiting without starting assessment.")
        raise SystemExit(1)


def get_ports_from_user():
    """Read comma-separated target ports from interactive CLI and validate range (1-65535)."""
    while True:
        user_input = _required_input("Port(s): ").strip()
        if not user_input:
            print("[-] Port(s) required. Example: 21,22,80")
            continue
        ports = parse_ports_string(user_input)
        if ports:
            return ports
        print("[-] Invalid port(s). Must be numbers between 1 and 65535.")


def _auto_port_auth_settings(port):
    """
    Automatically configure direct service timing measurement for supported ports (FTP/SSH)
    using the synthetic probe identity (config.DEFAULT_CALIBRATION_USER) without prompting.
    """
    if port == 21:
        return {
            "ftp_user": config.DEFAULT_CALIBRATION_USER,
            "authorize_auth_probes": True,
        }
    if port == 22 and getattr(ssh_adapter, "paramiko", None) is not None:
        return {
            "ssh_user": config.DEFAULT_CALIBRATION_USER,
            "authorize_auth_probes": True,
            "verify_host_key": True,
            "allow_untrusted_host_key": True,
        }
    return {}


def get_assessment_settings(ports=None):
    """Select an assessment mode and automatically configure direct service measurement."""
    print("\n--- Assessment Mode ---")
    print("1) Network Baseline Diagnostic (TCP Connection Establishment)")
    print("2) Dictionary Audit Planning (Wordlist / Candidate Count)")
    print("3) Exhaustive Search Space Planning (Brute-Force N^L)")

    choice = _required_input("Mode (1/2/3) [Default: 1]: ").strip()
    base = {
        "measure_protocol": True,
        "adaptive_sampling": True,
    }

    # Mode 1: Network Baseline Diagnostic
    if choice == "1" or not choice:
        settings = {"mode": "RTT_Only", **base}
    # Mode 2: Dictionary Audit Planning (accepts a wordlist file path OR a direct candidate count)
    elif choice == "2":
        raw_input = _required_input(
            f"Wordlist path or candidate count [Enter for default '{config.DEFAULT_WORDLIST}']: "
        ).strip()
        if raw_input.isdigit() and int(raw_input) > 0:
            settings = {"mode": "Dictionary_Audit", "candidates": int(raw_input), "path": None, **base}
        else:
            wordlist_path = raw_input if raw_input else config.DEFAULT_WORDLIST
            settings = {"mode": "Dictionary_Audit", "path": wordlist_path, **base}
    # Mode 3: Exhaustive Search Space Planning
    elif choice == "3":
        print("\n--- Character Sets ---")
        for key, (size, description) in config.CHARSETS.items():
            print(f"{key}) {description} (Size: {size})")

        charset_choice = _required_input("Charset (1-4) [Default: 2]: ").strip()
        if charset_choice not in config.CHARSETS:
            charset_choice = "2"

        try:
            length_input = int(_required_input("Password Length [Default: 6]: ").strip())
            length = length_input if length_input > 0 else 6
        except ValueError:
            length = 6

        settings = {
            "mode": "Permutation_Benchmark",
            "charset_key": charset_choice,
            "length": length,
            **base,
        }
    else:
        settings = {"mode": "RTT_Only", **base}

    # Measure service timing directly in Mode 2 and Mode 3 without extra prompts
    settings["port_auth"] = {}
    if settings["mode"] in ("Dictionary_Audit", "Permutation_Benchmark"):
        for port in dict.fromkeys(ports or []):
            auto_cfg = _auto_port_auth_settings(port)
            if auto_cfg:
                settings["port_auth"][port] = auto_cfg

    return settings


def resolve_mode_candidates(assessment_config):
    """
    Resolve candidate count and human-readable mode label independently of network probing.
    Reads any dictionary file at most once per session.
    """
    mode = assessment_config.get("mode", "RTT_Only")
    if mode == "RTT_Only":
        return None, "Network Baseline Diagnostic", None

    if mode == "Dictionary_Audit":
        explicit_candidates = assessment_config.get("candidates")
        if explicit_candidates is not None:
            if isinstance(explicit_candidates, bool) or not isinstance(explicit_candidates, int) or explicit_candidates < 0:
                raise ValueError("candidates must be a non-negative integer")
            return explicit_candidates, "Dictionary Planning", None

        requested_path = assessment_config.get("path")
        tries, used_path = calculator.count_wordlist(requested_path)
        if tries is None:
            print(f"[-] Error reading dictionary '{used_path}'. Falling back to default.")
            tries, used_path = calculator.count_wordlist(config.DEFAULT_WORDLIST)
            if tries is None:
                err = "Could not read the requested or default wordlist."
                print(f"[-] {err} Candidate count unavailable.")
                return None, "Dictionary Planning (Wordlist Unreadable)", err
        return tries, f"Dictionary Planning ({used_path})", None

    if mode == "Permutation_Benchmark":
        length = assessment_config.get("length", 6)
        charset_key = str(assessment_config.get("charset_key", "2"))
        tries, _, description = calculator.calculate_brute_force(length, charset_key)
        return tries, f"Exhaustive Search Planning ({description}, L={length})", None

    raise ValueError(f"Unsupported assessment mode: {mode}")


def _port_scan_options(ports, settings):
    """Validate the entire request before probing and bind credentials to explicit ports."""
    ports = list(dict.fromkeys(ports))
    proto = settings.get("protocol")
    if proto:
        proto = proto.strip().lower()
        if protocols.DEFAULT_REGISTRY.get_by_name(proto) is None:
            raise ValueError(f"Unsupported protocol adapter: {proto}")
        if len(ports) != 1:
            raise ValueError("--protocol requires exactly one distinct port; run separate commands for other ports")
    if settings.get("auth_user") is not None and not proto:
        raise ValueError("--auth-user requires an explicit --protocol and a single port")

    options = {port: ({"protocol": proto} if proto else {}) for port in ports}
    scoped = settings.get("port_auth")
    if scoped is not None:
        if any(settings.get(key) is not None for key in ("ftp_user", "ssh_user", "auth_user")):
            raise ValueError("Do not combine per-port and global authentication credentials")
        if any(port not in options for port in scoped):
            raise ValueError("Authentication configuration refers to an unselected port")
        for port, auth in scoped.items():
            options[port].update(auth)
    else:
        has_explicit_user = any(settings.get(k) is not None for k in ("ftp_user", "ssh_user", "auth_user"))
        for key, expected_proto, default_port in (("ftp_user", "ftp", 21), ("ssh_user", "ssh", 22), ("auth_user", proto, None)):
            user = settings.get(key)
            if user is None:
                continue
            if proto and proto != expected_proto:
                raise ValueError(f"{key} conflicts with protocol {proto}")
            port = ports[0] if proto else default_port
            if port not in options:
                raise ValueError(f"{key} has no matching selected port; specify --protocol for a nonstandard port")
            if any(options[port].get(k) is not None for k in ("ftp_user", "ssh_user", "auth_user")):
                raise ValueError("Only one test username may be configured per port")
            options[port].update({key: user, "authorize_auth_probes": settings.get("authorize_auth_probes", False)})

        # When --authorize-auth-probes is enabled without an explicit username, automatically assume
        # config.DEFAULT_CALIBRATION_USER ('nafat_probe') on supported protocol ports.
        if settings.get("authorize_auth_probes") and not has_explicit_user:
            assigned_any = False
            for port, opts in options.items():
                adapter = protocols.get_adapter_for_endpoint(port, opts.get("protocol"))
                if adapter.supports_auth_calibration:
                    user_key = f"{adapter.protocol_id}_user" if adapter.protocol_id in ("ftp", "ssh") else "auth_user"
                    opts[user_key] = config.DEFAULT_CALIBRATION_USER
                    opts["authorize_auth_probes"] = True
                    if adapter.protocol_id == "ssh" and settings.get("known_hosts_path") is None:
                        opts["allow_untrusted_host_key"] = True
                    assigned_any = True
            if not assigned_any:
                raise ValueError(
                    "Active calibration requires a supported protocol adapter (e.g. port 21 FTP, port 22 SSH, or --protocol)"
                )

    has_ssh_auth = False
    for port, opts in options.items():
        adapter = protocols.get_adapter_for_endpoint(port, opts.get("protocol"))
        users = [(key, opts[key]) for key in ("ftp_user", "ssh_user", "auth_user") if opts.get(key) is not None]
        if len(users) > 1:
            raise ValueError("Only one test username may be configured per port")
        if not users:
            if opts.get("authorize_auth_probes"):
                if adapter.supports_auth_calibration:
                    default_key = f"{adapter.protocol_id}_user" if adapter.protocol_id in ("ftp", "ssh") else "auth_user"
                    opts[default_key] = config.DEFAULT_CALIBRATION_USER
                    users = [(default_key, config.DEFAULT_CALIBRATION_USER)]
                else:
                    raise ValueError("Active calibration requires a supported protocol adapter for this port")
            else:
                continue
        key, user = users[0]
        if key in ("ftp_user", "ssh_user") and key != f"{adapter.protocol_id}_user":
            raise ValueError(f"{key} does not match the protocol on port {port}")
        opts[key] = adapter.validate_auth_request(user, opts.get("authorize_auth_probes", False))
        opts["protocol"] = adapter.protocol_id
        for name in ("max_reuse_probes", "auth_timeout_seconds"):
            if settings.get(name) is not None:
                opts[name] = settings[name]
        if adapter.protocol_id == "ssh":
            has_ssh_auth = True
            adapter.check_dependencies()
            for name in ("known_hosts_path", "handshake_timeout_seconds", "allow_untrusted_host_key"):
                if name not in opts and settings.get(name) is not None:
                    opts[name] = settings[name]
            opts["verify_host_key"] = True
    if settings.get("allow_untrusted_host_key") and not has_ssh_auth:
        raise ValueError("--allow-untrusted-host-key requires authorized SSH calibration")
    return options


def _unexpected_auth_success(scan_result):
    """Recognize both generic and backward-compatible protocol calibration summaries."""
    for key, summary in scan_result.items():
        if key != "auth_calibration" and not key.endswith("_auth"):
            continue
        if not isinstance(summary, dict):
            continue
        if (summary.get("calibration_status") == "INVALID_CALIBRATION"
                or summary.get("successful_count", 0) > 0
                or "unexpected_auth_success" in summary.get("termination_reasons", [])):
            return True
        for session in summary.get("sessions", []):
            if (session.get("termination_reason") == "unexpected_auth_success"
                    or any(p.get("outcome") == "successful" for p in session.get("probes", []))):
                return True
    return False


def run_assessment(target_ips, ports, assessment_config):
    """Execute TCP connection measurements and network planning calculations across unique endpoints."""
    port_options = _port_scan_options(ports, assessment_config)
    tries, audit_type_str, candidate_space_error = resolve_mode_candidates(assessment_config)
    sample_size = assessment_config.get("sample_size", config.PROBE_SAMPLE_SIZE)
    pause_seconds = assessment_config.get("pause_seconds", config.PROBE_INTERVAL_SECONDS)
    timeout_seconds = assessment_config.get("timeout_seconds", config.CONNECTION_TIMEOUT)
    budget_hours = assessment_config.get("budget_hours", config.DEFAULT_PLANNING_BUDGET_HOURS)
    measure_protocol = bool(assessment_config.get("measure_protocol", False))
    adaptive_sampling = bool(assessment_config.get("adaptive_sampling", False))
    client_attempts_per_conn = assessment_config.get("client_attempts_per_conn")

    assessment_results = {}
    print("\n[*] Starting TCP Connection Establishment Measurement...")

    for target_ip in target_ips:
        for port in ports:
            endpoint = f"{target_ip}:{port}"
            if endpoint in assessment_results:
                continue  # Deduplicate repeated target:port inputs

            print(f"[+] Measuring {endpoint} ({sample_size} TCP Attempts)...")
            scan_kwargs = dict(port_options[port])
            if measure_protocol or port == 21:
                scan_kwargs["measure_protocol"] = True
            if adaptive_sampling:
                scan_kwargs["adaptive_sampling"] = True

            scan_res = scanner.scan_target(
                target_ip,
                port,
                sample_size=sample_size,
                pause_seconds=pause_seconds,
                timeout_seconds=timeout_seconds,
                **scan_kwargs,
            )

            calc_kwargs = {}
            if client_attempts_per_conn is not None:
                calc_kwargs["client_attempts_per_conn"] = client_attempts_per_conn

            plan_res = calculator.calculate_feasibility(
                tries,
                max_hours=budget_hours,
                scan_result=scan_res,
                mode=assessment_config["mode"],
                candidate_space_error=candidate_space_error,
                **calc_kwargs,
            )
            assessment_results[endpoint] = {
                **scan_res,
                **plan_res,
                "audit_mode": audit_type_str,
                "assessment_mode": assessment_config["mode"],
                "candidate_space_error": candidate_space_error,
            }
            if _unexpected_auth_success(scan_res):
                assessment_results[endpoint]["assessment_termination_reason"] = "unexpected_auth_success"
                print("[-] Unexpected authentication success: stopping assessment across all remaining targets and ports.")
                return assessment_results

    return assessment_results


def build_arg_parser():
    """Build command-line argument parser supporting all THREE operational modes."""
    parser = argparse.ArgumentParser(
        description="NAFAT v1.2 — Network Authentication Feasibility Assessment Tool"
    )
    parser.add_argument("--target", "-t", required=True, help="Comma-separated target IPv4 address(es) or hostname(s)")
    parser.add_argument("--port", "-p", required=True, help="Comma-separated target port(s), e.g. 22,80")
    parser.add_argument(
        "--mode", "-m",
        choices=["1", "2", "3"],
        default="1",
        help="Operational mode: 1=Network Baseline Diagnostic, 2=Dictionary Planning, 3=Exhaustive Search Planning",
    )
    parser.add_argument("--wordlist", "-w", default=None, help="Wordlist file path for Mode 2")
    parser.add_argument("--candidates", "-c", type=int, default=None, help="Explicit candidate count for Mode 2")
    parser.add_argument("--charset", choices=["1", "2", "3", "4"], default="2", help="Charset option (1-4) for Mode 3")
    parser.add_argument("--length", "-l", type=int, default=6, help="Password length (>=1) for Mode 3")
    parser.add_argument(
        "--budget-hours",
        type=float,
        default=config.DEFAULT_PLANNING_BUDGET_HOURS,
        help=f"Network planning time budget in hours (default: {config.DEFAULT_PLANNING_BUDGET_HOURS})",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=config.PROBE_SAMPLE_SIZE,
        help=f"Number of TCP connection attempts per endpoint (default: {config.PROBE_SAMPLE_SIZE})",
    )
    parser.add_argument(
        "--pacing-ms",
        type=float,
        default=config.PROBE_INTERVAL_SECONDS * 1000.0,
        help=f"Inter-attempt pause in milliseconds (default: {config.PROBE_INTERVAL_SECONDS * 1000.0:.0f})",
    )
    parser.add_argument(
        "--measure-protocol",
        action="store_true",
        help="Measure dynamic post-connect protocol greeting overhead across TCP samples",
    )
    parser.add_argument(
        "--protocol",
        default=None,
        help="Explicit protocol adapter selection (e.g. ftp, ssh) for protocol timing or nonstandard ports",
    )
    parser.add_argument(
        "--ftp-user",
        default=None,
        help=f"Optional FTP calibration username (defaults to '{config.DEFAULT_CALIBRATION_USER}' when --authorize-auth-probes is used)",
    )
    parser.add_argument(
        "--ssh-user",
        default=None,
        help=f"Optional SSH calibration username (defaults to '{config.DEFAULT_CALIBRATION_USER}' when --authorize-auth-probes is used)",
    )
    parser.add_argument(
        "--auth-user",
        default=None,
        help=f"Optional protocol calibration username (defaults to '{config.DEFAULT_CALIBRATION_USER}' when --authorize-auth-probes is used)",
    )
    parser.add_argument(
        "--authorize-auth-probes",
        action="store_true",
        help="Explicitly confirm authorization to send active authentication calibration probes (state-changing operation)",
    )
    parser.add_argument(
        "--auth-timeout",
        type=float,
        default=config.FTP_AUTH_TIMEOUT,
        help=f"Maximum waiting timeout in seconds for authentication responses (default: {config.FTP_AUTH_TIMEOUT})",
    )
    parser.add_argument(
        "--ssh-handshake-timeout",
        type=float,
        default=config.SSH_HANDSHAKE_TIMEOUT,
        help=f"Maximum waiting timeout in seconds for SSH cryptographic handshake (default: {config.SSH_HANDSHAKE_TIMEOUT})",
    )
    parser.add_argument(
        "--known-hosts",
        default=None,
        help="Path to SSH known_hosts file for host-key verification during active SSH calibration",
    )
    parser.add_argument(
        "--allow-untrusted-host-key",
        action="store_true",
        help="Separately confirm lab-only use of unverified SSH host keys (requires authorized SSH calibration)",
    )
    parser.add_argument(
        "--auth-samples",
        type=int,
        default=None,
        help=(
            f"Maximum sequential authentication probes per test connection "
            f"(default: {config.FTP_MAX_REUSE_PROBES} for FTP, {config.SSH_MAX_REUSE_PROBES} for SSH)"
        ),
    )
    parser.add_argument(
        "--client-attempts-per-conn",
        type=int,
        default=None,
        help="Optional client-side authentication attempts per TCP connection (K_client)",
    )
    return parser


def config_from_cli_args(args):
    """Map parsed CLI arguments accurately to Mode 1, Mode 2, or Mode 3 configuration."""
    if args.samples < 1:
        raise ValueError("--samples must be a positive integer")
    if not math.isfinite(args.pacing_ms) or args.pacing_ms < 0:
        raise ValueError("--pacing-ms must be non-negative")
    if not math.isfinite(args.budget_hours) or args.budget_hours <= 0:
        raise ValueError("--budget-hours must be positive")
    if not math.isfinite(args.auth_timeout) or args.auth_timeout <= 0:
        raise ValueError("--auth-timeout must be positive")
    ssh_hs_timeout = getattr(args, "ssh_handshake_timeout", config.SSH_HANDSHAKE_TIMEOUT)
    if ssh_hs_timeout is not None and (not math.isfinite(ssh_hs_timeout) or ssh_hs_timeout <= 0):
        raise ValueError("--ssh-handshake-timeout must be positive")
    if args.auth_samples is not None and args.auth_samples < 1:
        raise ValueError("--auth-samples must be a positive integer")

    raw_proto = getattr(args, "protocol", None)
    if raw_proto is not None and not str(raw_proto).strip():
        raise ValueError("--protocol must be a non-empty protocol name")
    proto = str(raw_proto).strip().lower() if raw_proto is not None else None

    raw_ftp_user = getattr(args, "ftp_user", None)
    raw_ssh_user = getattr(args, "ssh_user", None)
    raw_auth_user = getattr(args, "auth_user", None)

    if raw_ftp_user is not None:
        if not str(raw_ftp_user).strip():
            raise ValueError("--ftp-user must be a non-empty username")
        if not args.authorize_auth_probes:
            raise ValueError("--ftp-user requires explicit --authorize-auth-probes confirmation")
    if raw_ssh_user is not None:
        if not str(raw_ssh_user).strip():
            raise ValueError("--ssh-user must be a non-empty username")
        if not args.authorize_auth_probes:
            raise ValueError("--ssh-user requires explicit --authorize-auth-probes confirmation")
    if raw_auth_user is not None:
        if not str(raw_auth_user).strip():
            raise ValueError("--auth-user must be a non-empty username")
        if not args.authorize_auth_probes:
            raise ValueError("--auth-user requires explicit --authorize-auth-probes confirmation")

    has_any_user = any(u is not None for u in (raw_ftp_user, raw_ssh_user, raw_auth_user))
    if proto == "ftp" and raw_ssh_user is not None:
        raise ValueError("--ssh-user cannot be combined with --protocol ftp")
    if proto == "ssh" and raw_ftp_user is not None:
        raise ValueError("--ftp-user cannot be combined with --protocol ssh")

    raw_known_hosts = getattr(args, "known_hosts", None)
    if raw_known_hosts is not None and not str(raw_known_hosts).strip():
        raise ValueError("--known-hosts must be a non-empty file path")
    known_hosts_path = str(raw_known_hosts).strip() if raw_known_hosts is not None else None
    allow_untrusted_hk = bool(getattr(args, "allow_untrusted_host_key", False))

    if args.client_attempts_per_conn is not None and args.client_attempts_per_conn < 1:
        raise ValueError("--client-attempts-per-conn must be a positive integer")

    active_proto_or_auth = bool(args.measure_protocol or has_any_user or args.authorize_auth_probes or proto is not None)
    common = {
        "sample_size": args.samples,
        "pause_seconds": args.pacing_ms / 1000.0,
        "budget_hours": args.budget_hours,
        "measure_protocol": active_proto_or_auth,
        "adaptive_sampling": active_proto_or_auth,
        "protocol": proto,
        "ftp_user": str(raw_ftp_user).strip() if raw_ftp_user else None,
        "ssh_user": str(raw_ssh_user).strip() if raw_ssh_user else None,
        "auth_user": str(raw_auth_user).strip() if raw_auth_user else None,
        "authorize_auth_probes": bool(args.authorize_auth_probes),
        "auth_timeout_seconds": args.auth_timeout,
        "handshake_timeout_seconds": ssh_hs_timeout,
        "known_hosts_path": known_hosts_path,
        "verify_host_key": True,
        "allow_untrusted_host_key": allow_untrusted_hk,
        "max_reuse_probes": args.auth_samples,
        "client_attempts_per_conn": args.client_attempts_per_conn,
    }
    if args.mode == "1":
        return {"mode": "RTT_Only", **common}
    if args.mode == "2":
        if args.candidates is not None and args.candidates < 0:
            raise ValueError("--candidates must be non-negative")
        return {
            "mode": "Dictionary_Audit",
            "path": args.wordlist if args.wordlist else config.DEFAULT_WORDLIST,
            "candidates": args.candidates,
            **common,
        }
    if args.mode == "3":
        if args.length < 1:
            raise ValueError("--length must be a positive integer")
        return {
            "mode": "Permutation_Benchmark",
            "charset_key": args.charset,
            "length": args.length,
            **common,
        }
    raise ValueError(f"Invalid mode: {args.mode}")


def main(argv=None):
    """Run NAFAT either via command-line arguments or interactive prompts."""
    if argv is not None and len(argv) > 0:
        args = build_arg_parser().parse_args(argv)
        target_ips = validate_ip_list(args.target)
        if not target_ips:
            raise ValueError(f"Invalid or unresolvable target IP(s): {args.target}")
        ports = parse_ports_string(args.port)
        if not ports:
            raise ValueError(f"Invalid port(s): {args.port}. Must be integers between 1 and 65535.")
        assessment_config = config_from_cli_args(args)
        assessment_results = run_assessment(target_ips, ports, assessment_config)
        report_text = report.build_report_text(assessment_results)
        txt_file, json_file = report.save_reports(assessment_results, report_text)
        print("\n" + report_text)
        print(f"\n[+] TXT Report saved: {txt_file}")
        print(f"[+] JSON Report saved: {json_file}")
        return assessment_results

    print("=" * 67)
    print("   NETWORK AUTHENTICATION FEASIBILITY ASSESSMENT TOOL (NAFAT)")
    print("=" * 67)

    while True:
        ip_input = _required_input("\nTarget IP(s): ").strip()
        target_ips = validate_ip_list(ip_input)
        if target_ips:
            break
        print("[-] Invalid IPv4 format or unresolvable hostname. Try again.")

    ports = get_ports_from_user()
    assessment_config = get_assessment_settings(ports=ports)
    assessment_results = run_assessment(target_ips, ports, assessment_config)

    report_text = report.build_report_text(assessment_results)
    txt_file, json_file = report.save_reports(assessment_results, report_text)

    print("\n" + report_text)
    print(f"\n[+] TXT Report saved: {txt_file}")
    print(f"[+] JSON Report saved: {json_file}")
    return assessment_results


if __name__ == "__main__":
    try:
        main(sys.argv[1:] if len(sys.argv) > 1 else None)
    except KeyboardInterrupt:
        print("\n\n[-] Assessment cancelled by user (Ctrl+C). Exiting safely.")
        sys.exit(0)
    except ValueError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        sys.exit(2)
