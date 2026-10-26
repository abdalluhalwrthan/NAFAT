# scanner.py
# Client-observed TCP connection establishment timing, statistical summary, and non-invasive banner observation.

import errno
import ipaddress
import socket
import statistics
import time
from datetime import datetime, timezone

import config
import protocols


def _read_ftp_response(s):
    """
    Read a complete single-line or multi-line FTP response (RFC 959).
    Waits for newline-terminated lines before evaluating single-line ('XYZ ')
    or multi-line ('XYZ-' ... 'XYZ ') completion.
    Returns (status_code_str, first_line_str, full_response_str).
    """
    return protocols.read_ftp_response(s)


def measure_protocol_greeting(s, target_ip, port, protocol=None, registry=None):
    """
    Measure dynamic protocol setup overhead strictly after TCP connect() completes.
    Delegates to the registered ProtocolAdapter for the endpoint while passing
    scanner.time.perf_counter so offline deterministic clock tests work seamlessly.
    Returns (concise_display_banner, banner_info_dict, protocol_elapsed_seconds, protocol_outcome).
    """
    adapter = protocols.get_adapter_for_endpoint(port=port, protocol_name=protocol, registry=registry)
    return adapter.measure_setup(s, target_ip, port, clock_fn=time.perf_counter)


def grab_banner(s, target_ip, port):
    """
    Attempt a banner read after TCP connection establishment.
    Never performs TLS handshakes or authentication attempts.
    Returns (concise_display_banner, banner_info_dict).
    """
    display, info, _, _ = measure_protocol_greeting(s, target_ip, port)
    return display, info


def measure_ftp_auth_session(s, username=None, reject_token=None, max_reuse_probes=None,
                             auth_timeout_seconds=None, authorize_auth_probes=False):
    """
    Execute an explicitly authorized FTP authentication probe sequence on an open FTP socket
    after the 220 service greeting has been consumed.
    Requires authorize_auth_probes=True explicitly; missing authorization never enables probes.
    Applies a dedicated authentication response timeout (default 10.0s) and restores the
    previous socket timeout upon completion.
    """
    return protocols.FTP_ADAPTER.measure_auth_session(
        s,
        username,
        reject_token=reject_token,
        max_reuse_probes=max_reuse_probes,
        auth_timeout_seconds=auth_timeout_seconds,
        authorize_auth_probes=authorize_auth_probes,
        clock_fn=time.perf_counter,
    )


def measure_ssh_auth_session(
    s,
    username=None,
    reject_token=None,
    max_reuse_probes=None,
    auth_timeout_seconds=None,
    authorize_auth_probes=False,
    handshake_timeout_seconds=None,
    target_ip="127.0.0.1",
    port=22,
    known_hosts_path=None,
    verify_host_key=True,
    allow_untrusted_host_key=False,
    transport_factory=None,
):
    """
    Execute an explicitly authorized SSH cryptographic handshake and failed-authentication
    calibration sequence on a connected socket via SSHAdapter.
    Requires authorize_auth_probes=True explicitly; missing authorization never enables probes.
    Applies separate handshake and authentication timeouts and restores previous socket timeout.
    """
    return protocols.SSH_ADAPTER.measure_auth_session(
        s,
        username,
        reject_token=reject_token,
        max_reuse_probes=max_reuse_probes,
        auth_timeout_seconds=auth_timeout_seconds,
        authorize_auth_probes=authorize_auth_probes,
        handshake_timeout_seconds=handshake_timeout_seconds,
        target_ip=target_ip,
        port=port,
        known_hosts_path=known_hosts_path,
        verify_host_key=verify_host_key,
        allow_untrusted_host_key=allow_untrusted_host_key,
        transport_factory=transport_factory,
        clock_fn=time.perf_counter,
    )


def _record_failure(sample, exc):
    """Preserve original connection or setup error details even if socket close also raises."""
    if sample["stage"] != "tcp_connect":
        outcome = "error"
    elif isinstance(exc, socket.timeout) or getattr(exc, "errno", None) == errno.ETIMEDOUT:
        outcome = "timeout"
    elif isinstance(exc, ConnectionRefusedError) or getattr(exc, "errno", None) == errno.ECONNREFUSED:
        outcome = "refused"
    else:
        outcome = "error"
    sample.update(
        outcome=outcome,
        error_type=type(exc).__name__,
        error_errno=getattr(exc, "errno", None),
        error_message=str(exc),
    )


def classify_variability(mean_ms, std_ms, success_count):
    """
    Compute Coefficient of Variation (CV = SD / Mean) and classify observed jitter/variability
    within the sample window where statistically meaningful (n >= 2 and mean > 0).
    """
    if success_count < 2 or mean_ms is None or std_ms is None or mean_ms <= 0:
        return {
            "cv_ratio": None,
            "cv_percent": None,
            "classification": "INDETERMINATE",
            "summary": "Requires >= 2 successful TCP samples with positive mean",
        }
    cv_ratio = std_ms / mean_ms
    cv_pct = cv_ratio * 100.0
    if cv_ratio < config.CV_LOW_THRESHOLD:
        level = "LOW"
    elif cv_ratio < config.CV_MODERATE_THRESHOLD:
        level = "MODERATE"
    else:
        level = "HIGH"
    return {
        "cv_ratio": cv_ratio,
        "cv_percent": cv_pct,
        "classification": level,
        "summary": f"{level} (CV: {cv_pct:.2f}%)",
    }


def determine_port_status(attempt_count, success_count, refused_count, timeout_count, error_count):
    """Classify endpoint TCP status transparently from observed attempt outcomes."""
    if success_count > 0:
        if success_count == attempt_count:
            return "OPEN"
        return f"OPEN (Partial Loss: {success_count}/{attempt_count})"
    if refused_count > 0 and timeout_count == 0 and error_count == 0:
        return "CLOSED (Connection Refused)"
    if timeout_count > 0 and refused_count == 0 and error_count == 0:
        return "UNREACHABLE / FILTERED (Timeout)"
    if error_count > 0 and refused_count == 0 and timeout_count == 0:
        return "UNREACHABLE (Network Error)"
    return "INDETERMINATE (Mixed Failure Outcomes)"


def _summarize_stage_ms(values_sec):
    """Compute sample mean, sample SD, min, max, and standard error in milliseconds."""
    n = len(values_sec)
    if n == 0:
        return {
            "count": 0,
            "mean_ms": None,
            "std_ms": None,
            "min_ms": None,
            "max_ms": None,
            "se_ms": None,
            "cv_ratio": None,
            "cv_percent": None,
        }
    mean_s = statistics.mean(values_sec)
    std_s = statistics.stdev(values_sec) if n >= 2 else None
    min_s = min(values_sec)
    max_s = max(values_sec)
    mean_ms = mean_s * 1000.0
    std_ms = std_s * 1000.0 if std_s is not None else None
    se_ms = (std_ms / (n ** 0.5)) if (std_ms is not None and n >= 2) else None
    cv_ratio = (std_ms / mean_ms) if (std_ms is not None and mean_ms > 0) else None
    return {
        "count": n,
        "mean_ms": mean_ms,
        "std_ms": std_ms,
        "min_ms": min_s * 1000.0,
        "max_ms": max_s * 1000.0,
        "se_ms": se_ms,
        "cv_ratio": cv_ratio,
        "cv_percent": (cv_ratio * 100.0) if cv_ratio is not None else None,
    }


def _summarize_auth_sessions(auth_sessions, auth_timeout_seconds, protocol_id="ftp", handshake_timeout_seconds=None):
    """
    Summarize authentication calibration probe sessions (FTP, SSH, or custom protocol adapters)
    into a unified statistical and session-reuse structure while retaining protocol-specific metrics.
    Failed-authentication statistics are computed strictly from rejected_probes only.
    """
    all_probes = [p for sess in auth_sessions for p in sess.get("probes", [])]
    rejected_probes = [
        p for p in all_probes
        if p.get("outcome") == "rejected" and p.get("auth_total_seconds") is not None
    ]
    successful_probes = [
        p for p in all_probes
        if p.get("outcome") == "successful" and p.get("auth_total_seconds") is not None
    ]
    completed_probes = [
        p for p in all_probes
        if p.get("outcome") in ("rejected", "successful") and p.get("auth_total_seconds") is not None
    ]
    termination_events = [p for p in all_probes if p.get("outcome") == "server_limit_disconnect"]
    timeout_probes = [p for p in all_probes if p.get("outcome") == "timeout"]
    closed_probes = [p for p in all_probes if p.get("outcome") == "connection_closed"]
    error_probes = [p for p in all_probes if p.get("outcome") == "error"]
    failed_probe_count = len(timeout_probes) + len(closed_probes) + len(error_probes)
    session_errors = [sess.get("session_error") for sess in auth_sessions if sess.get("session_error")]

    has_unexpected_success = (
        len(successful_probes) > 0
        or any(sess.get("termination_reason") == "unexpected_auth_success" for sess in auth_sessions)
    )

    # Failed-authentication timing statistics use ONLY rejected_probes (never mixed with successful_probes)
    auth_total_sec = [p["auth_total_seconds"] for p in rejected_probes]
    user_cmd_sec = [p["user_cmd_seconds"] for p in rejected_probes if p.get("user_cmd_seconds") is not None]
    pass_cmd_sec = [p["pass_cmd_seconds"] for p in rejected_probes if p.get("pass_cmd_seconds") is not None]
    succ_auth_sec = [p["auth_total_seconds"] for p in successful_probes]

    auth_stats = _summarize_stage_ms(auth_total_sec)
    user_stats = _summarize_stage_ms(user_cmd_sec)
    pass_stats = _summarize_stage_ms(pass_cmd_sec)
    succ_auth_stats = _summarize_stage_ms(succ_auth_sec)

    usable_capacities = [
        sess["completed_attempts_in_connection"]
        for sess in auth_sessions
        if sess.get("completed_attempts_in_connection", 0) > 0
    ]
    clean_limit_capacities = [
        sess["completed_attempts_in_connection"]
        for sess in auth_sessions
        if sess.get("termination_reason") == "server_limit_after_auth"
        and sess.get("completed_attempts_in_connection", 0) > 0
    ]
    unexpected_failures = [
        sess for sess in auth_sessions
        if sess.get("termination_reason") in (
            "mid_exchange_disconnect",
            "closed_after_auth_unknown_cause",
            "timeout",
            "handshake_timeout",
            "transport_error",
            "protocol_error",
            "account_restriction",
            "unsupported_algorithms",
            "handshake_error",
            "host_key_unverified",
            "password_auth_unsupported",
            "unexpected_auth_success",
        )
    ]
    max_observed_usable = max(usable_capacities) if usable_capacities else None
    if (
        clean_limit_capacities
        and not unexpected_failures
        and len(set(clean_limit_capacities)) == 1
        and (max_observed_usable is None or max_observed_usable == clean_limit_capacities[0])
    ):
        exact_k_srv = clean_limit_capacities[0]
        lower_bound_k_srv = exact_k_srv
        is_lower_bound = False
    else:
        exact_k_srv = None
        lower_bound_k_srv = max_observed_usable
        is_lower_bound = (lower_bound_k_srv is not None)

    disconnect_overheads = [
        sess["disconnect_detection_seconds"]
        for sess in auth_sessions
        if sess.get("disconnect_detection_seconds") is not None
    ]
    disconnect_stats = _summarize_stage_ms(disconnect_overheads)
    any_closed = any(sess.get("server_closed_connection") for sess in auth_sessions)

    failure_details = []
    if session_errors:
        failure_details.append(f"{len(session_errors)} session setup/handshake failed ({session_errors[0]})")
    if timeout_probes:
        first_to_err = timeout_probes[0].get("error") or "socket timeout"
        failure_details.append(f"{len(timeout_probes)} timed out ({first_to_err})")
    if closed_probes:
        first_cl_err = closed_probes[0].get("error") or "connection closed"
        failure_details.append(f"{len(closed_probes)} closed unexpectedly ({first_cl_err})")
    if error_probes:
        first_er = error_probes[0].get("error") or "protocol/transport error"
        failure_details.append(f"{len(error_probes)} errored ({first_er})")

    if has_unexpected_success:
        calibration_status = "INVALID_CALIBRATION"
        failure_summary = (
            f"INVALID_CALIBRATION: unexpected successful authentication observed "
            f"({len(successful_probes)} probe(s) succeeded; calibration halted immediately)"
        )
    elif len(rejected_probes) == 0:
        calibration_status = "UNAVAILABLE"
        reason_str = "; ".join(failure_details) if failure_details else "no valid rejected authentication responses received"
        if len(all_probes) == 0:
            failure_summary = f"0 auth probes sent ({reason_str})"
        else:
            failure_summary = f"0/{len(all_probes)} auth probes completed ({reason_str})"
    elif len(unexpected_failures) > 0:
        calibration_status = "PARTIAL"
        reason_str = "; ".join(failure_details) if failure_details else "session anomaly"
        failure_summary = f"{len(rejected_probes)}/{len(all_probes)} auth probes completed ({reason_str})"
    else:
        calibration_status = "MEASURED"
        failure_summary = None

    summary = {
        "protocol": protocol_id,
        "calibration_status": calibration_status,
        "session_count": len(auth_sessions),
        "probe_attempt_count": len(all_probes),
        "completed_count": len(completed_probes),
        "rejected_count": len(rejected_probes),
        "successful_count": len(successful_probes),
        "termination_event_count": len(termination_events),
        "failed_count": failed_probe_count,
        "timeout_count": len(timeout_probes),
        "connection_closed_count": len(closed_probes),
        "error_count": len(error_probes),
        "unexpected_session_failure_count": len(unexpected_failures),
        "failure_summary": failure_summary,
        "auth_timeout_seconds": auth_timeout_seconds,
        "auth_mean_ms": None if has_unexpected_success else auth_stats["mean_ms"],
        "auth_std_ms": None if has_unexpected_success else auth_stats["std_ms"],
        "auth_min_ms": None if has_unexpected_success else auth_stats["min_ms"],
        "auth_max_ms": None if has_unexpected_success else auth_stats["max_ms"],
        "auth_se_ms": None if has_unexpected_success else auth_stats["se_ms"],
        "auth_cv_percent": None if has_unexpected_success else auth_stats["cv_percent"],
        "successful_auth_mean_ms": succ_auth_stats["mean_ms"],
        "user_cmd_mean_ms": None if has_unexpected_success else user_stats["mean_ms"],
        "pass_cmd_mean_ms": None if has_unexpected_success else pass_stats["mean_ms"],
        "disconnect_detection_mean_ms": disconnect_stats["mean_ms"],
        "observed_server_reuse_limit": None if has_unexpected_success else exact_k_srv,
        "observed_server_reuse_lower_bound": None if has_unexpected_success else lower_bound_k_srv,
        "reuse_limit_is_lower_bound": False if has_unexpected_success else is_lower_bound,
        "server_enforced_close_observed": any_closed,
        "termination_reasons": [sess.get("termination_reason") for sess in auth_sessions],
        "sessions": auth_sessions,
    }

    hs_secs = [
        sess["handshake_seconds"]
        for sess in auth_sessions
        if sess.get("handshake_outcome") == "success" and sess.get("handshake_seconds") is not None
    ]
    if hs_secs or protocol_id == "ssh":
        hs_stats = _summarize_stage_ms(hs_secs)
        summary["handshake_timeout_seconds"] = handshake_timeout_seconds or config.SSH_HANDSHAKE_TIMEOUT
        summary["handshake_mean_ms"] = hs_stats["mean_ms"]
        summary["handshake_std_ms"] = hs_stats["std_ms"]
        summary["handshake_min_ms"] = hs_stats["min_ms"]
        summary["handshake_max_ms"] = hs_stats["max_ms"]
        summary["handshake_se_ms"] = hs_stats["se_ms"]
        hk_statuses = [sess.get("host_key_status") for sess in auth_sessions if sess.get("host_key_status")]
        summary["host_key_status"] = hk_statuses[0] if hk_statuses else None
        allowed_lists = [sess.get("allowed_auth_types") for sess in auth_sessions if sess.get("allowed_auth_types") is not None]
        summary["allowed_auth_types"] = allowed_lists[0] if allowed_lists else None

    return summary


def summarize_samples(samples, sample_size, banner="Not Detected", banner_attempt=None,
                      banner_info=None, started_at=None, pause_seconds=None,
                      timeout_seconds=None, evidence_origin="measured",
                      adaptive_extended=False, ftp_auth_sessions=None,
                      auth_timeout_seconds=None, ssh_auth_sessions=None,
                      handshake_timeout_seconds=None, protocol_id=None,
                      protocol_supported=True, unsupported_protocol_reason=None,
                      protocol_capabilities=None, auth_sessions=None):
    """
    Compute verified statistical and rate summaries from raw TCP attempt samples,
    dynamic protocol setup overhead samples, and optional protocol authentication probe sessions.
    Separated from socket I/O so historical and regression fixtures use the exact same math.
    """
    if pause_seconds is None:
        pause_seconds = config.PROBE_INTERVAL_SECONDS
    if timeout_seconds is None:
        timeout_seconds = config.CONNECTION_TIMEOUT
    if auth_timeout_seconds is None:
        auth_timeout_seconds = config.FTP_AUTH_TIMEOUT
    if started_at is None:
        started_at = datetime.now(timezone.utc).isoformat()
    if banner_info is None:
        banner_info = {
            "status": "not_attempted" if not any(s.get("outcome") == "success" for s in samples) else "unknown",
            "display": banner,
            "raw_banner": banner if banner != "Not Detected" else None,
            "explanation": "No successful TCP connection to read banner from." if banner == "Not Detected" else "Banner recorded.",
        }

    successful_sec = [s["elapsed_seconds"] for s in samples if s.get("outcome") == "success" and s.get("elapsed_seconds") is not None]
    n_total = len(samples)
    n_succ = len(successful_sec)
    n_fail = n_total - n_succ
    n_timeout = sum(1 for s in samples if s.get("outcome") == "timeout")
    n_refused = sum(1 for s in samples if s.get("outcome") == "refused")
    n_error = sum(1 for s in samples if s.get("outcome") == "error")

    mean_sec = statistics.mean(successful_sec) if n_succ >= 1 else None
    std_sec = statistics.stdev(successful_sec) if n_succ >= 2 else None
    min_sec = min(successful_sec) if n_succ >= 1 else None
    max_sec = max(successful_sec) if n_succ >= 1 else None

    mean_ms = mean_sec * 1000.0 if mean_sec is not None else None
    std_ms = std_sec * 1000.0 if std_sec is not None else None
    min_ms = min_sec * 1000.0 if min_sec is not None else None
    max_ms = max_sec * 1000.0 if max_sec is not None else None

    success_rate_pct = (n_succ / n_total * 100.0) if n_total > 0 else 0.0
    failure_rate_pct = (n_fail / n_total * 100.0) if n_total > 0 else 0.0
    timeout_rate_pct = (n_timeout / n_total * 100.0) if n_total > 0 else 0.0
    refused_rate_pct = (n_refused / n_total * 100.0) if n_total > 0 else 0.0

    variability = classify_variability(mean_ms, std_ms, n_succ)
    port_status = determine_port_status(n_total, n_succ, n_refused, n_timeout, n_error)

    # Idealized sequential TCP connection-establishment model rate: 1 / mean_tcp_sec
    tcp_only_rate = (1.0 / mean_sec) if (mean_sec is not None and mean_sec > 0) else None
    # Paced sequential TCP cycle rate including configured inter-attempt pause
    paced_cycle_sec = (mean_sec + pause_seconds) if (mean_sec is not None and mean_sec > 0) else None
    paced_cycle_rate = (1.0 / paced_cycle_sec) if (paced_cycle_sec is not None and paced_cycle_sec > 0) else None

    # Dynamic protocol setup overhead summary (strictly post-connect greeting or SSH handshake)
    proto_succ_sec = [
        s["protocol_overhead_seconds"]
        for s in samples
        if s.get("protocol_outcome") == "success" and s.get("protocol_overhead_seconds") is not None
    ]
    proto_stats = _summarize_stage_ms(proto_succ_sec)
    proto_fail_count = sum(
        1 for s in samples
        if s.get("protocol_outcome") in ("timeout", "empty_response", "error")
    )

    grouped_sessions = {}
    seen_session_ids = set()
    seen_session_keys = set()

    def _collect_sessions(sess_list, default_proto):
        if not sess_list:
            return
        for sess in sess_list:
            if not isinstance(sess, dict):
                continue
            s_proto = str(sess.get("protocol") or default_proto or "generic").strip().lower()
            conn_att = sess.get("connection_attempt")
            if id(sess) in seen_session_ids or (conn_att is not None and (s_proto, conn_att) in seen_session_keys):
                continue
            seen_session_ids.add(id(sess))
            if conn_att is not None:
                seen_session_keys.add((s_proto, conn_att))
            grouped_sessions.setdefault(s_proto, []).append(sess)

    _collect_sessions(ftp_auth_sessions, "ftp")
    _collect_sessions(ssh_auth_sessions, "ssh")
    _collect_sessions(auth_sessions, protocol_id or "generic")

    summaries_by_proto = {}
    for s_proto, sess_group in grouped_sessions.items():
        summaries_by_proto[s_proto] = _summarize_auth_sessions(
            sess_group,
            auth_timeout_seconds=auth_timeout_seconds,
            protocol_id=s_proto,
            handshake_timeout_seconds=handshake_timeout_seconds,
        )

    result = {
        "is_open": n_succ > 0,
        "port_status": port_status,
        "measurement_type": "tcp_connection_establishment",
        "evidence_origin": evidence_origin,
        "started_at_utc": started_at,
        "tcp_connect_mean_ms": mean_ms,
        "tcp_connect_std_ms": std_ms,
        "tcp_connect_min_ms": min_ms,
        "tcp_connect_max_ms": max_ms,
        "tcp_connect_cv": variability["cv_ratio"],
        "tcp_connect_cv_percent": variability["cv_percent"],
        "variability_indicator": variability["classification"],
        "variability_summary": variability["summary"],
        "attempt_count": n_total,
        "success_count": n_succ,
        "failure_count": n_fail,
        "timeout_count": n_timeout,
        "refused_count": n_refused,
        "error_count": n_error,
        "success_rate_percent": success_rate_pct,
        "failure_rate_percent": failure_rate_pct,
        "timeout_rate_percent": timeout_rate_pct,
        "refused_rate_percent": refused_rate_pct,
        "network_model_rate_tcp_only_per_sec": tcp_only_rate,
        "network_model_rate_paced_per_sec": paced_cycle_rate,
        "banner": banner,
        "banner_attempt": banner_attempt,
        "banner_info": banner_info,
        "samples": samples,
        "sampling": {
            "requested_attempts": sample_size,
            "actual_attempts": n_total,
            "adaptive_sampling_triggered": adaptive_extended,
            "connection_timeout_seconds": timeout_seconds,
            "pause_between_attempts_seconds": pause_seconds,
            "clock": "time.perf_counter",
            "timed_operation": "socket.connect on a fresh IPv4 TCP socket",
            "statistics_population": "successful TCP connections only",
            "standard_deviation": "sample (n-1); unavailable with fewer than two successes",
            "excluded_stages": [
                "DNS",
                "socket construction",
                "banner I/O",
                "TLS",
                "authentication",
                "socket close",
                "inter-attempt pause",
            ],
            "limitations": [
                "Client and operating-system scheduling are included; this is TCP connection establishment, not raw packet RTT.",
                "1 / mean_tcp_seconds is an idealized sequential TCP connection model rate, not SSH authentication throughput or safe server capacity.",
                "A small baseline sample characterizes only the observed measurement window, not long-term path stability.",
                "Sample standard deviation describes sample dispersion, not a confidence interval.",
            ],
        },
    }

    if proto_stats["count"] > 0 or proto_fail_count > 0:
        result["protocol_overhead_mean_ms"] = proto_stats["mean_ms"]
        result["protocol_overhead_std_ms"] = proto_stats["std_ms"]
        result["protocol_overhead_min_ms"] = proto_stats["min_ms"]
        result["protocol_overhead_max_ms"] = proto_stats["max_ms"]
        result["protocol_overhead_se_ms"] = proto_stats["se_ms"]
        result["protocol_overhead_cv_percent"] = proto_stats["cv_percent"]
        result["protocol_sample_count"] = proto_stats["count"]
        result["protocol_failure_count"] = proto_fail_count

    for s_proto, auth_sum in summaries_by_proto.items():
        result[f"{s_proto}_auth"] = auth_sum

    active_proto = (
        protocol_id.strip().lower()
        if (isinstance(protocol_id, str) and protocol_id.strip())
        else str((banner_info or {}).get("protocol") or "").strip().lower()
    )
    if active_proto in summaries_by_proto:
        result["auth_calibration"] = summaries_by_proto[active_proto]
    elif active_proto in ("", "generic") and len(summaries_by_proto) == 1:
        result["auth_calibration"] = next(iter(summaries_by_proto.values()))

    if protocol_id is not None:
        result["protocol_id"] = protocol_id
        result["protocol_supported"] = bool(protocol_supported)
    if protocol_capabilities is not None:
        result["protocol_capabilities"] = protocol_capabilities
    if not protocol_supported and unsupported_protocol_reason:
        result["unsupported_protocol_reason"] = unsupported_protocol_reason

    return result


def scan_target(target_ip, port, sample_size=None, pause_seconds=None, timeout_seconds=None, *,
                measure_protocol=False, adaptive_sampling=False, ftp_user=None,
                ssh_user=None, auth_user=None, protocol=None,
                authorize_auth_probes=False, max_reuse_probes=None, auth_timeout_seconds=None,
                handshake_timeout_seconds=None, known_hosts_path=None,
                verify_host_key=True, allow_untrusted_host_key=False,
                transport_factory=None, registry=None):
    """
    Time socket.connect() on fresh IPv4 sockets; retain every attempted outcome.
    Timings bracket connect() only and exclude DNS, socket construction, banner I/O, and pacing.
    When measure_protocol=True (or active auth calibration is authorized), dynamically times
    post-connect protocol greeting / SSH handshake overhead without double-counting TCP establishment.
    Active authentication probes (FTP, SSH, or registered adapter) require authorize_auth_probes=True.
    If authorize_auth_probes=True and no username is provided, automatically assumes config.DEFAULT_CALIBRATION_USER.
    """
    target_ip = str(ipaddress.IPv4Address(target_ip))
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer from 1 to 65535")
    if sample_size is None:
        sample_size = config.PROBE_SAMPLE_SIZE
    if isinstance(sample_size, bool) or not isinstance(sample_size, int) or sample_size < 1:
        raise ValueError("sample_size must be a positive integer")
    if pause_seconds is None:
        pause_seconds = config.PROBE_INTERVAL_SECONDS
    if isinstance(pause_seconds, bool) or not isinstance(pause_seconds, (int, float)) or pause_seconds < 0:
        raise ValueError("pause_seconds must be a non-negative number")
    if timeout_seconds is None:
        timeout_seconds = config.CONNECTION_TIMEOUT
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be a positive number")
    if auth_timeout_seconds is None:
        auth_timeout_seconds = config.SSH_AUTH_TIMEOUT if (ssh_user is not None or protocol == "ssh" or port == 22) else config.FTP_AUTH_TIMEOUT
    if isinstance(auth_timeout_seconds, bool) or not isinstance(auth_timeout_seconds, (int, float)) or auth_timeout_seconds <= 0:
        raise ValueError("auth_timeout_seconds must be a positive number")
    if handshake_timeout_seconds is not None:
        if isinstance(handshake_timeout_seconds, bool) or not isinstance(handshake_timeout_seconds, (int, float)) or handshake_timeout_seconds <= 0:
            raise ValueError("handshake_timeout_seconds must be a positive number")
    if ftp_user is not None:
        if not isinstance(ftp_user, str) or not ftp_user.strip():
            raise ValueError("ftp_user must be a non-empty string when provided")
        if not authorize_auth_probes:
            raise ValueError("Active FTP authentication probes require authorize_auth_probes=True")
    if ssh_user is not None:
        if not isinstance(ssh_user, str) or not ssh_user.strip():
            raise ValueError("ssh_user must be a non-empty string when provided")
        if not authorize_auth_probes:
            raise ValueError("Active SSH authentication probes require authorize_auth_probes=True")
    if auth_user is not None:
        if not isinstance(auth_user, str) or not auth_user.strip():
            raise ValueError("auth_user must be a non-empty string when provided")
        if not authorize_auth_probes:
            raise ValueError("Active authentication probes require authorize_auth_probes=True")

    active_reg = registry if registry is not None else protocols.DEFAULT_REGISTRY
    explicit_proto = protocol.strip().lower() if (isinstance(protocol, str) and protocol.strip()) else None
    if explicit_proto is None:
        if ftp_user is not None:
            explicit_proto = "ftp"
        elif ssh_user is not None:
            explicit_proto = "ssh"

    protocol_supported = True
    unsupported_reason = None
    if explicit_proto is not None and active_reg.get_by_name(explicit_proto) is None:
        protocol_supported = False
        unsupported_reason = f"Protocol '{explicit_proto}' does not have a registered measurement adapter"

    adapter = protocols.get_adapter_for_endpoint(port=port, protocol_name=explicit_proto, registry=active_reg)
    effective_user = ftp_user or ssh_user or auth_user
    if effective_user is None and authorize_auth_probes and protocol_supported and adapter.supports_auth_calibration:
        effective_user = config.DEFAULT_CALIBRATION_USER

    started_at = datetime.now(timezone.utc).isoformat()
    samples = []
    banner = "Not Detected"
    banner_attempt = None
    banner_info = None
    auth_sessions = []
    adaptive_extended = False
    calibration_halted = False

    def _did_session_unexpectedly_succeed(sess):
        return (
            sess.get("termination_reason") == "unexpected_auth_success"
            or any(p.get("outcome") == "successful" for p in sess.get("probes", []))
        )

    def _adapter_combines_setup(cur_adapter):
        return bool(
            getattr(
                cur_adapter,
                "combines_setup_and_auth_session",
                cur_adapter.protocol_id == "ssh",
            )
        )

    def _run_probe_batch(start_idx, count):
        nonlocal banner, banner_attempt, banner_info, adapter, calibration_halted, effective_user
        for offset in range(count):
            attempt = start_idx + offset
            sample = {
                "attempt": attempt,
                "stage": "socket_setup",
                "outcome": None,
                "elapsed_seconds": None,
                "error_type": None,
                "error_errno": None,
                "error_message": None,
            }
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    try:
                        s.settimeout(timeout_seconds)
                        sample["stage"] = "tcp_connect"
                        start = time.perf_counter()
                        try:
                            s.connect((target_ip, port))
                        finally:
                            sample["elapsed_seconds"] = time.perf_counter() - start
                    except OSError as exc:
                        _record_failure(sample, exc)
                    else:
                        sample["outcome"] = "success"
                        combines_setup = _adapter_combines_setup(adapter)
                        is_combined_active_cal = (
                            effective_user is not None
                            and authorize_auth_probes
                            and protocol_supported
                            and adapter.supports_auth_calibration
                            and combines_setup
                            and not calibration_halted
                        )
                        sufficient_combined_cal = (
                            len(auth_sessions) >= 1
                            and auth_sessions[0].get("completed_attempts_in_connection", 0) >= 3
                        )
                        if is_combined_active_cal and len(auth_sessions) < config.MIN_AUTH_CALIBRATION_SESSIONS and not sufficient_combined_cal:
                            auth_sess = adapter.measure_auth_session(
                                s,
                                effective_user,
                                max_reuse_probes=max_reuse_probes,
                                auth_timeout_seconds=auth_timeout_seconds,
                                authorize_auth_probes=authorize_auth_probes,
                                handshake_timeout_seconds=handshake_timeout_seconds,
                                target_ip=target_ip,
                                port=port,
                                known_hosts_path=known_hosts_path,
                                verify_host_key=verify_host_key,
                                allow_untrusted_host_key=allow_untrusted_host_key,
                                transport_factory=transport_factory,
                                clock_fn=time.perf_counter,
                            )
                            auth_sess["connection_attempt"] = attempt
                            auth_sessions.append(auth_sess)
                            if _did_session_unexpectedly_succeed(auth_sess):
                                calibration_halted = True
                            sample["protocol_overhead_seconds"] = auth_sess.get("handshake_seconds")
                            sample["protocol_outcome"] = auth_sess.get("handshake_outcome")
                            if banner_attempt is None:
                                banner_attempt = attempt
                                rem_b = auth_sess.get("remote_banner")
                                banner = rem_b if rem_b else "Not Detected"
                                banner_info = {
                                    "status": "received" if rem_b else (auth_sess.get("handshake_outcome") or "error"),
                                    "display": banner,
                                    "raw_banner": rem_b,
                                    "protocol": adapter.protocol_id,
                                    "setup_stage": "ssh_cryptographic_handshake",
                                    "protocol_overhead_seconds": auth_sess.get("handshake_seconds"),
                                    "explanation": "SSH banner and cryptographic handshake measured via Transport.start_client().",
                                }
                        elif not (
                            effective_user is not None
                            and authorize_auth_probes
                            and protocol_supported
                            and adapter.supports_auth_calibration
                            and combines_setup
                        ):
                            should_read_greeting = (
                                (banner_attempt is None)
                                or measure_protocol
                                or (effective_user is not None and protocol_supported)
                            )
                            if should_read_greeting:
                                s.settimeout(timeout_seconds)
                                if measure_protocol or (effective_user is not None and protocol_supported):
                                    b_disp, b_info, proto_sec, proto_out = measure_protocol_greeting(
                                        s, target_ip, port, protocol=explicit_proto, registry=active_reg
                                    )
                                    sample["protocol_overhead_seconds"] = proto_sec
                                    sample["protocol_outcome"] = proto_out
                                else:
                                    b_disp, b_info = grab_banner(s, target_ip, port)
                                    proto_out = "success" if b_info.get("status") == "received" else b_info.get("status")
                                if banner_attempt is None:
                                    banner_attempt = attempt
                                    banner, banner_info = b_disp, b_info
                                    if explicit_proto is None and adapter.protocol_id == "generic":
                                        detected = active_reg.detect_from_banner(b_disp)
                                        if detected is not None:
                                            adapter = detected
                                            combines_setup = _adapter_combines_setup(adapter)
                                            if effective_user is None and authorize_auth_probes and protocol_supported and adapter.supports_auth_calibration:
                                                effective_user = config.DEFAULT_CALIBRATION_USER

                                if (
                                    effective_user is not None
                                    and authorize_auth_probes
                                    and protocol_supported
                                    and adapter.supports_auth_calibration
                                    and not combines_setup
                                    and proto_out == "success"
                                    and len(auth_sessions) < config.MIN_AUTH_CALIBRATION_SESSIONS
                                    and not calibration_halted
                                ):
                                    auth_sess = adapter.measure_auth_session(
                                        s,
                                        effective_user,
                                        max_reuse_probes=max_reuse_probes,
                                        auth_timeout_seconds=auth_timeout_seconds,
                                        authorize_auth_probes=authorize_auth_probes,
                                        clock_fn=time.perf_counter,
                                    )
                                    auth_sess["connection_attempt"] = attempt
                                    auth_sessions.append(auth_sess)
                                    if _did_session_unexpectedly_succeed(auth_sess):
                                        calibration_halted = True
            except OSError as exc:
                if sample["outcome"] is not None:
                    sample["cleanup_error"] = str(exc)
                else:
                    _record_failure(sample, exc)
            samples.append(sample)
            if offset < count - 1 and pause_seconds > 0:
                time.sleep(pause_seconds)

    _run_probe_batch(1, sample_size)

    # Bounded adaptive sampling when variability is HIGH (CV >= 0.35)
    if adaptive_sampling and sample_size < config.ADAPTIVE_MAX_SAMPLE_SIZE:
        succ_sec = [s["elapsed_seconds"] for s in samples if s.get("outcome") == "success" and s.get("elapsed_seconds") is not None]
        if len(succ_sec) >= 2:
            m_s = statistics.mean(succ_sec)
            sd_s = statistics.stdev(succ_sec)
            if m_s > 0 and (sd_s / m_s) >= config.CV_MODERATE_THRESHOLD:
                extra = min(sample_size, config.ADAPTIVE_MAX_SAMPLE_SIZE - sample_size)
                if extra > 0:
                    if pause_seconds > 0:
                        time.sleep(pause_seconds)
                    adaptive_extended = True
                    _run_probe_batch(sample_size + 1, extra)

    resolved_proto_id = explicit_proto if not protocol_supported else (
        adapter.protocol_id if adapter.protocol_id != "generic" else None
    )
    proto_caps = (
        adapter.identify_service(port, banner if banner != "Not Detected" else None)
        if resolved_proto_id is not None
        else None
    )

    return summarize_samples(
        samples=samples,
        sample_size=sample_size,
        banner=banner,
        banner_attempt=banner_attempt,
        banner_info=banner_info,
        started_at=started_at,
        pause_seconds=pause_seconds,
        timeout_seconds=timeout_seconds,
        evidence_origin="measured",
        adaptive_extended=adaptive_extended,
        auth_timeout_seconds=auth_timeout_seconds,
        handshake_timeout_seconds=handshake_timeout_seconds,
        protocol_id=resolved_proto_id,
        protocol_supported=protocol_supported,
        unsupported_protocol_reason=unsupported_reason,
        protocol_capabilities=proto_caps,
        auth_sessions=auth_sessions if auth_sessions else None,
    )