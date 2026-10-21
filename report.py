# report.py
# Compact, aligned, terminal-style TXT report formatting and collision-safe TXT/JSON persistence.

import json
import math
import os
from datetime import datetime
import config


KNOWN_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
}


def _single_line(value):
    """Escape control characters for safe single-line TXT rendering while keeping raw values in JSON."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in str(value))


def _extract_port(endpoint):
    """Extract numeric port from an 'ip:port' endpoint string if present."""
    if not isinstance(endpoint, str) or ":" not in endpoint:
        return None
    tail = endpoint.rsplit(":", 1)[-1].strip()
    return int(tail) if tail.isdigit() else None


def _format_service(endpoint, metrics):
    """Return a concise service name, preserving any non-default banner text safely."""
    port = _extract_port(endpoint)
    port_service = KNOWN_PORTS.get(port)
    banner_raw = metrics.get("banner")
    if banner_raw and str(banner_raw).strip() not in ("", "Not Detected", "N/A"):
        clean_banner = _single_line(str(banner_raw).strip())
        if clean_banner.upper() in KNOWN_PORTS.values():
            return clean_banner.upper()
        if port_service and clean_banner.upper().startswith(port_service.upper()):
            # For standard protocol banners (e.g. SSH-2.0-OpenSSH_...), return concise service
            # unless the banner contains non-printable control sequences that must be surfaced.
            if all(char.isprintable() for char in str(banner_raw).strip()):
                return port_service
            return f"{port_service} ({clean_banner})"
        return clean_banner
    return port_service if port_service else "Not Detected"


def _format_status(metrics):
    """Return a clean status label (OPEN, CLOSED, or UNREACHABLE)."""
    n_succ = metrics.get("success_count", 0)
    is_open = bool(metrics.get("is_open", n_succ > 0))
    if is_open:
        return "OPEN"
    n_refused = metrics.get("refused_count", 0)
    n_timeout = metrics.get("timeout_count", 0)
    n_error = metrics.get("error_count", 0)
    if n_refused > 0 and n_timeout == 0 and n_error == 0:
        return "CLOSED"
    return "UNREACHABLE"


def _effective_cycle_variability(metrics, auth_dict=None):
    """
    When active authentication timing is measured, compute variability across the
    effective authentication cycle (amortized TCP + setup + auth rejection) so
    sub-15ms LAN ARP/TCP wakeup jitter does not falsely report HIGH variability.
    """
    if isinstance(auth_dict, dict):
        rej_n = auth_dict.get("rejected_count", auth_dict.get("completed_count", 0)) or 0
        auth_m = auth_dict.get("auth_mean_ms")
        auth_sd = auth_dict.get("auth_std_ms")
        if rej_n >= 2 and auth_m is not None and auth_m > 0 and auth_sd is not None and auth_sd >= 0:
            tcp_m = metrics.get("tcp_connect_mean_ms") or 0.0
            tcp_sd = metrics.get("tcp_connect_std_ms") or 0.0
            proto_m = metrics.get("protocol_overhead_mean_ms") or auth_dict.get("handshake_mean_ms") or 0.0
            proto_sd = metrics.get("protocol_overhead_std_ms") or auth_dict.get("handshake_std_ms") or 0.0
            k_eff = metrics.get("effective_attempts_per_connection") or auth_dict.get("observed_server_reuse_limit") or 1
            cycle_m = ((tcp_m + proto_m) / max(1, k_eff)) + auth_m
            cycle_sd = math.hypot(tcp_sd / max(1, k_eff), proto_sd / max(1, k_eff), auth_sd)
            if cycle_m > 0:
                cv_ratio = cycle_sd / cycle_m
                cv_pct = cv_ratio * 100.0
                if cv_ratio < config.CV_LOW_THRESHOLD:
                    lvl = "LOW"
                elif cv_ratio < config.CV_MODERATE_THRESHOLD:
                    lvl = "MODERATE"
                else:
                    lvl = "HIGH"
                return lvl, cv_pct
    return metrics.get("variability_indicator"), metrics.get("tcp_connect_cv_percent")


def _format_variability(metrics, auth_dict=None):
    """Format variability classification and CV percentage cleanly."""
    n_succ = metrics.get("success_count", 0)
    level, cv_pct = _effective_cycle_variability(metrics, auth_dict=auth_dict)
    if level in ("LOW", "MODERATE", "HIGH") and cv_pct is not None:
        return f"{level} (CV: {cv_pct:.2f}%)"
    if n_succ == 1:
        return "INDETERMINATE (Single sample)"
    if n_succ >= 2:
        return "LOW (CV: 0.00%)"
    return "UNAVAILABLE"


def _format_mode_name(metrics):
    """Return a clean, path-free mode name for the Assessment Planning section."""
    mode_id = metrics.get("assessment_mode")
    if mode_id == "Dictionary_Audit":
        return "Dictionary Planning"
    if mode_id == "Permutation_Benchmark":
        return "Exhaustive Search Planning"
    if mode_id == "RTT_Only":
        return "Network Baseline Diagnostic"
    raw_mode = str(metrics.get("audit_mode", ""))
    if "Dictionary" in raw_mode:
        return "Dictionary Planning"
    if "Exhaustive" in raw_mode or "Permutation" in raw_mode:
        return "Exhaustive Search Planning"
    return "Network Baseline Diagnostic"


def _format_compact_time(seconds):
    """Format duration into a single clean unit without parenthetical clutter."""
    if seconds is None or not math.isfinite(seconds) or seconds < 0:
        return None
    if seconds < 60.0:
        return f"{seconds:.2f} seconds"
    if seconds < 3600.0:
        return f"{seconds / 60.0:.2f} minutes"
    if seconds < 86400.0:
        return f"{seconds / 3600.0:.2f} hours"
    if seconds < 86400.0 * 365.0:
        return f"{seconds / 86400.0:.2f} days"
    return f"{seconds / (86400.0 * 365.0):.2f} years"


def _format_dual_sec_time(seconds):
    """Format duration showing both seconds and minutes for sub-hour benchmarks (e.g., comparing with `time hydra`)."""
    if seconds is None or not math.isfinite(seconds) or seconds < 0:
        return None
    if seconds < 60.0:
        return f"{seconds:.2f}s"
    if seconds < 3600.0:
        return f"{seconds:.2f}s ({seconds / 60.0:.2f} minutes)"
    return _format_compact_time(seconds)


def _resolve_report_protocol(metrics):
    """
    Determine active protocol identifier ('ftp', 'ssh', etc.) strictly from authoritative
    metadata produced by scanner.py (protocol_id, protocol_capabilities, or banner_info.protocol).
    Never guesses protocol identity from raw '220' banners or port numbers (21/22).
    """
    if not isinstance(metrics, dict):
        return None
    proto = metrics.get("protocol_id")
    if isinstance(proto, str) and proto.strip():
        return proto.strip().lower()
    caps = metrics.get("protocol_capabilities")
    if isinstance(caps, dict):
        c_proto = caps.get("protocol_id")
        if isinstance(c_proto, str) and c_proto.strip() and c_proto.strip().lower() != "generic":
            return c_proto.strip().lower()
    b_proto = (metrics.get("banner_info") or {}).get("protocol")
    if isinstance(b_proto, str) and b_proto.strip() and b_proto.strip().lower() not in ("generic", "tls"):
        return b_proto.strip().lower()
    return None


def _is_report_auth_requested(auth_dict):
    """Return True if authentication calibration was requested for this auth summary dict."""
    if not isinstance(auth_dict, dict) or not bool(auth_dict):
        return False
    status = auth_dict.get("calibration_status")
    if status == "NOT_REQUESTED":
        return False
    if status in ("INVALID_CALIBRATION", "UNAVAILABLE", "PARTIAL", "MEASURED"):
        return True
    return (
        (auth_dict.get("session_count") or 0) > 0
        or (auth_dict.get("probe_attempt_count") or 0) > 0
        or (auth_dict.get("completed_count") or 0) > 0
        or (auth_dict.get("rejected_count") or 0) > 0
    )


def _infer_report_auth_protocol(metrics, auth_dict):
    """
    Determine the protocol of auth_dict using:
    1. Explicit auth_dict.get("protocol") when present.
    2. Otherwise, infer from the matching protocol-specific key (<proto>_auth) in metrics.
    Returns lowercase protocol string, '__conflicting__' if bound to multiple conflicting keys, or None.
    """
    if not isinstance(auth_dict, dict):
        return None
    explicit = auth_dict.get("protocol")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip().lower()
    if isinstance(metrics, dict):
        matched_protos = [
            k[:-5].strip().lower()
            for k, v in metrics.items()
            if k.endswith("_auth") and v is auth_dict and k[:-5].strip()
        ]
        unique_protos = set(matched_protos)
        if len(unique_protos) == 1:
            return matched_protos[0]
        if len(unique_protos) > 1:
            return "__conflicting__"
    return None


def _get_report_auth_summary(metrics):
    """
    Select the active protocol's authentication calibration summary without cross-protocol
    contamination or port/banner guessing.
    """
    if not isinstance(metrics, dict):
        return None
    active_proto = _resolve_report_protocol(metrics)
    if active_proto is not None:
        candidates = [
            metrics.get(f"{active_proto}_auth"),
            metrics.get("auth_calibration"),
        ]
    else:
        proto_auth_dicts = [
            val for key, val in metrics.items()
            if key.endswith("_auth") and _is_report_auth_requested(val)
        ]
        if len(proto_auth_dicts) > 1:
            return None
        candidates = [metrics.get("auth_calibration")] + proto_auth_dicts

    for cand in candidates:
        if not _is_report_auth_requested(cand):
            continue
        cand_proto = _infer_report_auth_protocol(metrics, cand)
        if cand_proto == "__conflicting__":
            continue
        if active_proto and cand_proto and cand_proto != active_proto:
            continue
        return cand
    return None


def _format_planning_result(metrics):
    """Format the time-budget comparison outcome."""
    if metrics.get("insufficient_planning_data") is True or metrics.get("auth_calibration_status") in (
        "UNAVAILABLE",
        "INVALID_CALIBRATION",
        "UNSUPPORTED_PROTOCOL",
    ):
        return "INSUFFICIENT DATA"
    budget_h = metrics.get("planning_budget_hours")
    if budget_h is None:
        budget_h = config.DEFAULT_PLANNING_BUDGET_HOURS
    b_str = f"{int(budget_h)}h" if float(budget_h).is_integer() else f"{budget_h:g}h"
    within = metrics.get("within_network_budget")
    if within is True:
        return f"WITHIN {b_str} NETWORK BUDGET"
    if within is False:
        return f"EXCEEDS {b_str} NETWORK BUDGET"
    return "ESTIMATE AVAILABLE"


def _network_warning(metrics, auth_dict=None):
    """Return a short warning string only when a condition materially affects interpretation."""
    warnings = []
    if metrics.get("evidence_origin") == "synthetic" or metrics.get("evidence_level") == "SYNTHETIC / DEMONSTRATION ONLY":
        warnings.append("SYNTHETIC / DEMONSTRATION ONLY (not live data)")

    n_total = metrics.get("attempt_count", 0)
    n_succ = metrics.get("success_count", 0)
    n_fail = metrics.get("failure_count", 0)
    n_timeout = metrics.get("timeout_count", 0)
    n_refused = metrics.get("refused_count", 0)

    if n_succ == 0:
        if n_refused > 0 and n_timeout == 0:
            warnings.append(f"All {n_total} TCP connection attempts were refused")
        elif n_timeout > 0 and n_refused == 0:
            warnings.append(f"All {n_total} TCP connection attempts timed out")
        elif n_total > 0:
            warnings.append(f"0/{n_total} TCP connection attempts succeeded")
        else:
            warnings.append("No successful TCP connections observed")
        return "; ".join(warnings)

    if n_fail > 0 and n_total > 0:
        warnings.append(f"Partial connection failure ({n_fail}/{n_total} attempts failed)")

    eff_level, _ = _effective_cycle_variability(metrics, auth_dict=auth_dict)
    if eff_level == "HIGH":
        warnings.append("High timing variability; collect additional samples")
    elif n_succ == 1:
        warnings.append("Single sample observed; repeat scan to measure variability")

    return "; ".join(warnings) if warnings else None


def build_report_text(data):
    """
    Generate a compact, aligned, terminal-style TXT report for CLI display and file storage.
    Calculates and displays planning metrics directly at the suggested service speed (-t N)
    without cluttering the report with single-threaded (-t 1) assumptions.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sep_eq = "=" * 64
    sep_dash = "-" * 64

    lines = [
        sep_eq,
        "             NAFAT | NETWORK ASSESSMENT REPORT",
        sep_eq,
        f"Generated On       : {timestamp}",
    ]

    any_full_auth = False
    full_auth_protocols = []
    any_proto_setup = False
    endpoints = list(data.items())
    for idx, (endpoint, metrics) in enumerate(endpoints):
        if idx > 0:
            lines.append("")
            lines.append(sep_dash)

        mode_name = _format_mode_name(metrics)
        is_mode1 = (mode_name == "Network Baseline Diagnostic")
        status_str = _format_status(metrics)
        service_str = _format_service(endpoint, metrics)

        active_proto = _resolve_report_protocol(metrics)
        auth_dict = _get_report_auth_summary(metrics)
        auth_proto = _infer_report_auth_protocol(metrics, auth_dict) if auth_dict is not None else None
        auth_attempted = (
            auth_dict is not None
            or metrics.get("auth_calibration_status") in ("UNAVAILABLE", "INVALID_CALIBRATION", "PARTIAL", "MEASURED")
        )
        unsupported_proto = (
            metrics.get("protocol_supported") is False
            or metrics.get("auth_calibration_status") == "UNSUPPORTED_PROTOCOL"
        )

        proto_ms = metrics.get("protocol_overhead_mean_ms")
        if proto_ms is None and auth_dict is not None and auth_dict.get("handshake_mean_ms") is not None:
            proto_ms = auth_dict.get("handshake_mean_ms")

        cal_status = (
            metrics.get("auth_calibration_status")
            or (auth_dict.get("calibration_status") if auth_dict else None)
        )
        is_invalid_cal = (
            cal_status == "INVALID_CALIBRATION"
            or ((auth_dict.get("successful_count") or 0) > 0 if auth_dict else False)
        )
        rej_count = (
            0 if is_invalid_cal else (
                auth_dict.get("rejected_count", auth_dict.get("completed_count", 0))
                if auth_dict else 0
            )
        )
        auth_ms = (
            auth_dict.get("auth_mean_ms")
            if (auth_dict and not is_invalid_cal and not unsupported_proto and rej_count > 0)
            else None
        )
        auth_fail_reason = (
            metrics.get("auth_failure_summary")
            or (auth_dict.get("failure_summary") if auth_dict else None)
            or metrics.get("unsupported_protocol_reason")
            or "insufficient valid authentication samples"
        )

        if auth_proto == "__conflicting__" or (auth_proto and active_proto and auth_proto != active_proto):
            resolved_proto = None
        else:
            resolved_proto = auth_proto or active_proto
        proto_label = str(resolved_proto).upper() if resolved_proto else "UNKNOWN"

        is_ssh_handshake = (
            proto_label == "SSH"
            and (
                (metrics.get("banner_info") or {}).get("setup_stage") == "ssh_cryptographic_handshake"
                or (auth_dict is not None and auth_dict.get("handshake_mean_ms") is not None)
            )
        )

        if proto_ms is not None:
            any_proto_setup = True
        if auth_ms is not None:
            any_full_auth = True
            footer_proto = proto_label if proto_label != "UNKNOWN" else "protocol"
            if footer_proto not in full_auth_protocols:
                full_auth_protocols.append(footer_proto)

        setup_rate = metrics.get("protocol_setup_rate_per_sec")
        suggested_seq_rate = metrics.get("suggested_sequential_rate_per_sec")
        suggested_tasks = metrics.get("suggested_parallel_tasks")
        rate_unit = "sessions/sec" if proto_ms is not None else "connections/sec"

        # 1. TARGET section
        lines.extend([
            "",
            "[+] TARGET",
            f"    Endpoint       : {_single_line(endpoint)}",
            f"    Service        : {service_str}",
            f"    Status         : {status_str}",
        ])
        if unsupported_proto and active_proto:
            lines.append(f"    Protocol       : {_single_line(active_proto.upper())} (UNSUPPORTED ADAPTER)")
        elif active_proto and (metrics.get("protocol_capabilities") or auth_attempted):
            lines.append(f"    Protocol       : {_single_line(proto_label)}")

        # 2. NETWORK CONDITIONS section
        lines.append("")
        lines.append("[+] NETWORK CONDITIONS")
        mean_ms = metrics.get("tcp_connect_mean_ms")
        tcp_rate = metrics.get("network_model_rate_tcp_only_per_sec")
        if mean_ms is not None and status_str == "OPEN":
            lines.append(f"    TCP Latency    : {mean_ms:.2f} ms")
            if proto_ms is not None:
                setup_tag = "SSH Handshake" if is_ssh_handshake else "Post-TCP Greeting"
                lines.append(f"    Protocol Setup : {proto_ms:.2f} ms ({setup_tag})")
            if auth_dict is not None and auth_dict.get("host_key_status"):
                hk = auth_dict.get("host_key_status")
                if hk == "verified":
                    lines.append("    Host Key       : VERIFIED (known_hosts)")
                elif hk == "unverified_lab_opt_in":
                    lines.append("    Host Key       : UNVERIFIED (Lab Opt-In --allow-untrusted-host-key)")
                elif hk == "unverified_rejected":
                    lines.append("    Host Key       : REJECTED (Unverified Host Key)")
            if auth_ms is not None:
                user_ms = auth_dict.get("user_cmd_mean_ms")
                pass_ms = auth_dict.get("pass_cmd_mean_ms")
                att_n = auth_dict.get("probe_attempt_count", rej_count)
                if user_ms is not None and pass_ms is not None:
                    lines.append(
                        f"    Failed Auth    : {auth_ms:.2f} ms (USER: {user_ms:.2f} ms, PASS: {pass_ms:.2f} ms; {rej_count}/{att_n} probes)"
                    )
                elif proto_label == "SSH":
                    lines.append(f"    Failed Auth    : {auth_ms:.2f} ms (SSH userauth; {rej_count}/{att_n} probes)")
                elif proto_label == "FTP":
                    lines.append(f"    Failed Auth    : {auth_ms:.2f} ms (FTP USER/PASS; {rej_count}/{att_n} probes)")
                else:
                    stage_tag = f"{proto_label} auth" if proto_label != "UNKNOWN" else "Unknown protocol auth"
                    lines.append(f"    Failed Auth    : {auth_ms:.2f} ms ({stage_tag}; {rej_count}/{att_n} probes)")
                k_exact = auth_dict.get("observed_server_reuse_limit")
                k_lb = auth_dict.get("observed_server_reuse_lower_bound")
                if k_exact is not None:
                    lines.append(f"    Server Reuse   : {k_exact} attempts/conn (Confirmed Limit)")
                elif k_lb is not None:
                    lines.append(f"    Server Reuse   : At least {k_lb} attempts/conn (Lower Bound)")
            elif auth_attempted or unsupported_proto:
                lines.append(f"    Failed Auth    : UNAVAILABLE ({_single_line(auth_fail_reason)})")
            lines.append(f"    Variability    : {_format_variability(metrics, auth_dict=auth_dict if auth_ms is not None else None)}")
            if is_mode1 and tcp_rate is not None:
                lines.append(f"    Estimated Rate : {tcp_rate:.2f} TCP connections/sec")
                if setup_rate is not None:
                    setup_tag = "SSH Handshake" if is_ssh_handshake else "Protocol Greeting"
                    lines.append(f"    Setup Rate     : {setup_rate:.2f} sessions/sec (TCP + {setup_tag})")
        else:
            lines.append("    TCP Latency    : Unavailable")

        net_warn = _network_warning(metrics, auth_dict=auth_dict if auth_ms is not None else None)
        if net_warn:
            lines.append(f"    Warning        : {_single_line(net_warn)}")

        # 3. ASSESSMENT PLANNING section (Modes 2 and 3 only)
        if not is_mode1:
            lines.append("")
            lines.append("[+] ASSESSMENT PLANNING")
            lines.append(f"    Mode           : {mode_name}")

            total_tries = metrics.get("total_tries")
            cand_err = metrics.get("candidate_space_error")
            tcp_cost_sec = metrics.get("tcp_only_time_cost_seconds")
            setup_cost_sec = metrics.get("protocol_adjusted_time_cost_seconds")
            full_cost_sec = metrics.get("full_workload_time_cost_seconds")
            auth_rate_min = metrics.get("effective_auth_rate_per_min")
            auth_rate_sec = metrics.get("effective_auth_rate_per_sec")
            sugg_srv_min = metrics.get("suggested_service_auth_rate_per_min")
            sugg_srv_sec = metrics.get("suggested_service_auth_rate_per_sec")
            mean_srv_min = metrics.get("mean_service_auth_rate_per_min")
            mean_srv_sec = metrics.get("mean_service_auth_rate_per_sec")
            sugg_srv_time = metrics.get("suggested_service_workload_seconds")
            mean_srv_time = metrics.get("mean_service_workload_seconds")
            srv_range_min = metrics.get("service_target_range_min_seconds")
            srv_range_max = metrics.get("service_target_range_max_seconds")
            proj_min = metrics.get("sample_based_projection_range_min_seconds")
            proj_max = metrics.get("sample_based_projection_range_max_seconds")
            conf_level = metrics.get("measurement_confidence")
            unverified = metrics.get("unverified_assumptions") or []

            if total_tries is not None:
                lines.append(f"    Workload       : {total_tries:,} candidates")

            if status_str == "OPEN" and total_tries is not None and tcp_rate is not None and tcp_cost_sec is not None:
                if full_cost_sec is not None and auth_rate_min is not None and auth_rate_sec is not None:
                    # Direct protocol-native metrics (Attempt Cost, Service Speed, Full Auth Time, Sample Range)
                    n_tasks = suggested_tasks or 1
                    k_eff = metrics.get("effective_attempts_per_connection", 1)
                    est_conns = metrics.get("estimated_connections_required")
                    attempt_cost_sec = (full_cost_sec / total_tries) if total_tries > 0 else (1.0 / auth_rate_sec)
                    eff_srv_min = sugg_srv_min if sugg_srv_min is not None else auth_rate_min * n_tasks
                    eff_srv_sec = sugg_srv_sec if sugg_srv_sec is not None else auth_rate_sec * n_tasks
                    eff_mean_min = mean_srv_min if mean_srv_min is not None else auth_rate_min * n_tasks
                    eff_mean_sec = mean_srv_sec if mean_srv_sec is not None else auth_rate_sec * n_tasks
                    eff_srv_time = sugg_srv_time if sugg_srv_time is not None else (full_cost_sec / n_tasks)
                    eff_mean_time = mean_srv_time if mean_srv_time is not None else (full_cost_sec / n_tasks)
                    eff_r_min = srv_range_min if srv_range_min is not None else (proj_min / n_tasks if proj_min is not None else None)
                    eff_r_max = srv_range_max if srv_range_max is not None else (proj_max / n_tasks if proj_max is not None else None)

                    lines.append(
                        f"    Attempt Cost   : {attempt_cost_sec:.2f} sec/attempt "
                        f"(K={k_eff} attempts/conn, {est_conns:,} connections)"
                    )
                    lines.append(
                        f"    Concurrency    : {n_tasks} parallel sessions (Hydra: -t {n_tasks})"
                    )
                    if abs(eff_mean_min - eff_srv_min) > 0.05:
                        lines.append(
                            f"    Service Speed  : {eff_srv_min:.2f} - {eff_mean_min:.2f} attempts/min "
                            f"({eff_srv_sec:.2f} - {eff_mean_sec:.2f} attempts/sec)"
                        )
                    else:
                        lines.append(
                            f"    Service Speed  : {eff_srv_min:.2f} attempts/min ({eff_srv_sec:.2f} attempts/sec)"
                        )
                    if abs(eff_srv_time - eff_mean_time) > 0.05:
                        lines.append(
                            f"    Full Auth Time : {_format_dual_sec_time(eff_mean_time)} to {_format_dual_sec_time(eff_srv_time)} "
                            f"(K={k_eff}, {est_conns:,} connections)"
                        )
                    else:
                        lines.append(
                            f"    Full Auth Time : {_format_dual_sec_time(eff_srv_time)} (K={k_eff}, {est_conns:,} connections)"
                        )
                    if eff_r_min is not None and eff_r_max is not None:
                        lines.append(
                            f"    Sample Range   : {_format_dual_sec_time(eff_r_min)} to {_format_dual_sec_time(eff_r_max)} "
                            "(Sample-Based Projection Range)"
                        )
                else:
                    lines.append(f"    Estimated Rate : {tcp_rate:.2f} TCP connections/sec")
                    if setup_rate is not None:
                        setup_plan_tag = "SSH Handshake" if is_ssh_handshake else "Protocol Greeting"
                        lines.append(f"    Setup Rate     : {setup_rate:.2f} sessions/sec (TCP + {setup_plan_tag})")
                    lines.append(f"    Estimated Time : {_format_compact_time(tcp_cost_sec)}")
                    if setup_cost_sec is not None:
                        setup_plan_tag = "SSH Handshake" if is_ssh_handshake else "Protocol Greeting"
                        lines.append(f"    Setup Time     : {_format_compact_time(setup_cost_sec)} (TCP + {setup_plan_tag})")
                    if auth_attempted or unsupported_proto:
                        lines.append(f"    Full Auth Time : UNAVAILABLE ({_single_line(auth_fail_reason)})")

                if conf_level:
                    lines.append(f"    Confidence     : {_single_line(conf_level)}")
                for note in unverified:
                    lines.append(f"    Assumption     : {_single_line(note)}")
                lines.append(f"    Planning       : {_format_planning_result(metrics)}")
            elif cand_err:
                lines.append("    Planning       : UNAVAILABLE (Wordlist unreadable)")
                lines.append(f"    Warning        : {_single_line(cand_err)}")
            else:
                lines.append("    Planning       : UNAVAILABLE (Target port not open)")

    if any_full_auth:
        proto_str = "/".join(full_auth_protocols) if full_auth_protocols else "protocol"
        footer = [
            "",
            sep_dash,
            "Note: Includes measured TCP latency, protocol greeting overhead,",
            f"and authorized {proto_str} failed-authentication timing.",
            sep_eq,
        ]
    elif any_proto_setup:
        footer = [
            "",
            sep_dash,
            "Note: Includes measured TCP latency and protocol greeting setup;",
            "authentication verification time is excluded.",
            sep_eq,
        ]
    else:
        footer = [
            "",
            sep_dash,
            "Note: TCP-only estimate. Assumes one sequential TCP",
            "connection per candidate; authentication time is excluded.",
            sep_eq,
        ]
    lines.extend(footer)
    return "\n".join(lines)


def save_reports(data, report_text, reports_dir=None):
    """
    Save assessment results as both formatted TXT and raw JSON files under reports/.
    Validates strict JSON serialization (allow_nan=False) and uses exclusive file
    creation ("x" mode) with collision suffixes so existing reports are never overwritten.
    """
    target_dir = reports_dir or config.REPORTS_DIR
    os.makedirs(target_dir, exist_ok=True)

    json_text = json.dumps(data, indent=4, allow_nan=False)
    filename_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M%S")
    suffix = 0
    while True:
        stem = f"report_{filename_timestamp}" + (f"_{suffix}" if suffix else "")
        txt_path = os.path.join(target_dir, stem + ".txt")
        json_path = os.path.join(target_dir, stem + ".json")
        if os.path.exists(json_path):
            suffix += 1
            continue
        try:
            txt_file = open(txt_path, "x", encoding="utf-8")
        except FileExistsError:
            suffix += 1
            continue
        try:
            json_file = open(json_path, "x", encoding="utf-8")
        except FileExistsError:
            txt_file.close()
            os.remove(txt_path)
            suffix += 1
            continue
        except OSError:
            txt_file.close()
            raise
        with txt_file, json_file:
            txt_file.write(report_text)
            json_file.write(json_text)
        break

    return txt_path, json_path
