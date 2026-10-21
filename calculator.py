# calculator.py
# Candidate-space calculations, network connection time-cost models, and planning assessments.

import math
import statistics
import config
import protocols


def count_wordlist(path=None):
    """
    Read a wordlist file in binary mode and count unique non-empty stripped byte lines.
    Supports mixed-encoding wordlists (such as rockyou.txt) without UnicodeDecodeError
    and without merging or dropping non-UTF-8 byte sequences.
    Defaults to config.DEFAULT_WORDLIST if no path is provided.
    """
    if not path or str(path).strip() == "":
        path = config.DEFAULT_WORDLIST

    try:
        with open(path, "rb") as f:
            unique_words = {entry for line in f if (entry := line.strip())}
        return len(unique_words), str(path)
    except OSError:
        return None, str(path)


def calculate_brute_force(password_length, charset_key):
    """
    Calculate exhaustive mathematical candidate space (N^L) from config.CHARSETS.
    Returns (combinations, charset_size, charset_description).
    """
    if isinstance(password_length, bool) or not isinstance(password_length, int) or password_length < 1:
        raise ValueError("password_length must be a positive integer")
    if charset_key not in config.CHARSETS:
        charset_key = "2"

    charset_size, charset_description = config.CHARSETS[charset_key]
    combinations = charset_size ** password_length

    return combinations, charset_size, charset_description


def format_duration(seconds):
    """Format a duration in seconds into human-readable units."""
    if seconds is None or not math.isfinite(seconds) or seconds < 0:
        return None
    if seconds < 60.0:
        return f"{seconds:.2f} Seconds"
    if seconds < 3600.0:
        return f"{seconds / 60.0:.2f} Minutes ({seconds:.2f} s)"
    if seconds < 86400.0:
        return f"{seconds / 3600.0:.2f} Hours ({seconds / 60.0:.2f} Minutes)"
    if seconds < 86400.0 * 365.0:
        return f"{seconds / 86400.0:.2f} Days ({seconds / 3600.0:.2f} Hours)"
    return f"{seconds / (86400.0 * 365.0):.2f} Years ({seconds / 86400.0:,.1f} Days)"


def evaluate_workload_prediction(predicted_seconds, actual_runs_seconds, interval_bounds=None):
    """
    Compute empirical prediction error metrics when independently observed workload
    durations exist. Never fabricates validation metrics when actual runs are absent.
    """
    if isinstance(predicted_seconds, bool) or not isinstance(predicted_seconds, (int, float)) or not math.isfinite(predicted_seconds) or predicted_seconds <= 0:
        raise ValueError("predicted_seconds must be a finite positive number")
    if not isinstance(actual_runs_seconds, (list, tuple)) or len(actual_runs_seconds) == 0:
        raise ValueError("actual_runs_seconds must be a non-empty sequence of positive numbers")

    actuals = []
    for val in actual_runs_seconds:
        if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val) or val <= 0:
            raise ValueError("Each actual workload duration must be a finite positive number")
        actuals.append(float(val))

    errors = []
    for idx, actual in enumerate(actuals, start=1):
        signed = predicted_seconds - actual
        abs_err = abs(signed)
        rel_err = abs_err / actual
        covered = None
        if interval_bounds is not None and len(interval_bounds) == 2:
            low, high = interval_bounds
            if low is not None and high is not None:
                covered = (low <= actual <= high)
        errors.append({
            "run_index": idx,
            "actual_seconds": actual,
            "predicted_seconds": float(predicted_seconds),
            "signed_error_seconds": signed,
            "absolute_error_seconds": abs_err,
            "relative_error": rel_err,
            "percentage_error": rel_err * 100.0,
            "within_bounds": covered,
        })

    mae = statistics.mean(e["absolute_error_seconds"] for e in errors)
    mape = statistics.mean(e["percentage_error"] for e in errors)
    if not math.isfinite(mape):
        raise ValueError("Derived MAPE overflowed finite bounds")

    coverage = None
    if any(e["within_bounds"] is not None for e in errors):
        coverage = sum(1 for e in errors if e["within_bounds"]) / len(errors)

    return {
        "run_count": len(actuals),
        "predicted_seconds": float(predicted_seconds),
        "actual_mean_seconds": statistics.mean(actuals),
        "mean_absolute_error_seconds": mae,
        "mean_absolute_percentage_error": mape,
        "bounds_coverage_rate": coverage,
        "runs": errors,
    }


def _derive_planning_conclusions(scan_result, mode, total_tries, tcp_only_sec, paced_sec,
                                 budget_hours, candidate_space_error=None):
    """Build transparent Red Team and Blue Team planning guidance from observed metrics."""
    n_total = scan_result.get("attempt_count", 0)
    n_succ = scan_result.get("success_count", 0)
    n_fail = scan_result.get("failure_count", 0)
    n_timeout = scan_result.get("timeout_count", 0)
    n_refused = scan_result.get("refused_count", 0)
    var_level = scan_result.get("variability_indicator", "INDETERMINATE")
    cv_pct = scan_result.get("tcp_connect_cv_percent")
    mean_ms = scan_result.get("tcp_connect_mean_ms")

    if n_succ == 0:
        if n_refused == n_total and n_total > 0:
            reason = "All TCP connection probes were actively refused (RST) by the target."
        elif n_timeout == n_total and n_total > 0:
            reason = "All TCP connection probes timed out without a handshake response."
        else:
            reason = f"0/{n_total} TCP probes succeeded ({n_refused} refused, {n_timeout} timed out)."
        return {
            "planning_assessment": f"Endpoint unreachable for TCP planning ({reason})",
            "red_team_guidance": (
                f"{reason} Do not schedule online assessment workflows against this port unless "
                "network routing, firewall rules, or service state change."
            ),
            "blue_team_guidance": (
                f"{reason} No TCP service responsiveness observed from this vantage point; "
                "verify whether the port is intentionally closed/filtered or experiencing an outage."
            ),
            "variability_recommendation": "Collect reachability diagnostics from an authorized network segment if service is expected to be up.",
        }

    loss_note = ""
    if n_fail > 0:
        loss_note = f"; {n_fail}/{n_total} probes failed ({n_timeout} timeouts, {n_refused} refused)"

    var_note = ""
    var_rec = "Observed TCP connection timing was consistent across the 10-sample window."
    if var_level == "HIGH" and cv_pct is not None:
        var_note = f"; high jitter (CV {cv_pct:.1f}%)—collect more samples"
        var_rec = (
            f"High timing variability detected (CV {cv_pct:.2f}% >= 35%). Collect a larger sample "
            "across multiple intervals before relying on point rate estimates."
        )
    elif var_level == "MODERATE" and cv_pct is not None:
        var_note = f"; moderate jitter (CV {cv_pct:.1f}%)"
        var_rec = (
            f"Moderate timing variability detected (CV {cv_pct:.2f}%). Consider repeating baseline "
            "measurements to verify path stability."
        )
    elif var_level == "LOW" and cv_pct is not None:
        var_note = f"; low jitter (CV {cv_pct:.1f}%)"
    elif n_succ == 1:
        var_note = "; single sample (SD unavailable)"
        var_rec = "Only 1 successful connection was observed; repeat probing to establish timing variability."

    if mode == "RTT_Only":
        assessment = f"TCP connectivity verified (Mean {mean_ms:.2f} ms{var_note}{loss_note})"
        red_guidance = (
            f"Endpoint is reachable (mean TCP connect {mean_ms:.2f} ms{loss_note}). "
            "Use Mode 2 or Mode 3 to estimate cumulative TCP connection time costs for a specific candidate workload."
        )
        blue_guidance = (
            f"Service accepted {n_succ}/{n_total} TCP handshakes (mean {mean_ms:.2f} ms{var_note}). "
            "This baseline records transport responsiveness only and does not measure authentication capacity or IDS thresholds."
        )
        return {
            "planning_assessment": assessment,
            "red_team_guidance": red_guidance,
            "blue_team_guidance": blue_guidance,
            "variability_recommendation": var_rec,
        }

    if candidate_space_error or total_tries is None:
        return {
            "planning_assessment": f"TCP reachable (Mean {mean_ms:.2f} ms), but candidate space could not be loaded",
            "red_team_guidance": "Provide a valid UTF-8 wordlist or positive candidate count to compute network time costs.",
            "blue_team_guidance": f"Service accepted {n_succ}/{n_total} TCP handshakes (mean {mean_ms:.2f} ms).",
            "variability_recommendation": var_rec,
        }

    raw_proto = scan_result.get("protocol_id")
    unsupported_proto = _is_protocol_unsupported(scan_result)
    active_auth = _get_active_auth_summary(scan_result)
    auth_requested = _is_auth_calibration_requested(active_auth)
    auth_status = _get_auth_calibration_status(active_auth)
    rejected_cnt = _get_rejected_probe_count(active_auth)
    probe_attempts = _get_auth_probe_attempt_count(active_auth)
    auth_mean_val = active_auth.get("auth_mean_ms") if (auth_requested and active_auth) else None
    has_valid_auth = (
        auth_requested
        and auth_status not in ("INVALID_CALIBRATION", "UNAVAILABLE", "NOT_REQUESTED")
        and rejected_cnt > 0
        and auth_mean_val is not None
        and auth_mean_val > 0
    )

    if unsupported_proto or (auth_requested and not has_valid_auth):
        if unsupported_proto:
            reason_msg = (
                scan_result.get("unsupported_protocol_reason")
                or f"Protocol '{str(raw_proto or '').strip()}' does not have a registered timing adapter"
            )
        elif auth_status == "INVALID_CALIBRATION":
            reason_msg = (
                active_auth.get("failure_summary")
                or "INVALID_CALIBRATION: unexpected successful authentication invalidated calibration"
            )
        elif probe_attempts == 0:
            fail_sum = active_auth.get("failure_summary") if active_auth else None
            reason_msg = (
                f"Authentication calibration requested, but 0 authentication probes were sent ({fail_sum})"
                if fail_sum
                else "Authentication calibration requested, but session/handshake failed before any authentication probe was sent"
            )
        else:
            fail_sum = active_auth.get("failure_summary") if active_auth else None
            reason_msg = f"Authentication calibration unavailable ({fail_sum})" if fail_sum else "Authentication calibration unavailable"
        return {
            "planning_assessment": f"INSUFFICIENT DATA — {reason_msg}; Full Auth Time unavailable (TCP-only lower bound is not a valid full-authentication feasibility decision)",
            "red_team_guidance": (
                f"{reason_msg}. Do not treat the TCP-only baseline ({format_duration(tcp_only_sec)}) as an "
                "authentication feasibility approval; resolve calibration before scheduling online audits."
            ),
            "blue_team_guidance": (
                f"Service accepted {n_succ}/{n_total} TCP handshakes (mean {mean_ms:.2f} ms{var_note}), "
                f"but full authentication timing could not be validated ({reason_msg})."
            ),
            "variability_recommendation": var_rec,
        }

    budget_sec = budget_hours * 3600.0 if (budget_hours is not None and budget_hours > 0) else None
    if budget_sec is not None and tcp_only_sec is not None:
        if tcp_only_sec <= budget_sec:
            budget_label = f"Within {budget_hours:.1f}h network budget"
            red_budget = (
                f"Estimated network-only TCP connection time ({format_duration(tcp_only_sec)}) is within the "
                f"{budget_hours:.1f}-hour planning budget under a 1-connection-per-candidate assumption. "
                "Actual protocol negotiation and password verification will add time beyond this lower bound."
            )
            blue_budget = (
                f"Pure TCP handshake overhead for {total_tries:,} sequential connections requires only "
                f"{format_duration(tcp_only_sec)} (or {format_duration(paced_sec)} with 50ms pacing). "
                "Network latency alone does not constrain this workload; enforce application-layer rate limiting, "
                "authentication delays, or account lockouts."
            )
        else:
            budget_label = f"Exceeds {budget_hours:.1f}h network budget"
            red_budget = (
                f"Even before any authentication or protocol overhead, establishing {total_tries:,} sequential "
                f"TCP connections requires {format_duration(tcp_only_sec)}, exceeding the {budget_hours:.1f}-hour "
                "planning budget. Narrow the candidate space before testing."
            )
            blue_budget = (
                f"Sequential TCP connection establishment alone for {total_tries:,} candidates exceeds "
                f"{budget_hours:.1f} hours ({format_duration(tcp_only_sec)}) under a 1-connection-per-candidate model. "
                "Note that connection reuse or concurrency would alter this network-only baseline."
            )
    else:
        budget_label = "Network time cost estimated"
        red_budget = f"Estimated sequential TCP connection time is {format_duration(tcp_only_sec)} (excludes auth overhead)."
        blue_budget = f"Sequential TCP connection baseline for {total_tries:,} candidates is {format_duration(tcp_only_sec)}."

    assessment = f"{budget_label} (1 conn/candidate TCP model; excludes auth time{var_note}{loss_note})"
    return {
        "planning_assessment": assessment,
        "red_team_guidance": red_budget,
        "blue_team_guidance": blue_budget,
        "variability_recommendation": var_rec,
    }


def _resolve_active_protocol(scan_result):
    """
    Determine the active protocol identifier ('ftp', 'ssh', or any registered adapter id)
    strictly from authoritative scan_result metadata (protocol_id, protocol_capabilities,
    or banner_info.protocol). Returns lowercase protocol string or None if unspecified.
    """
    if not isinstance(scan_result, dict):
        return None
    proto = scan_result.get("protocol_id")
    if isinstance(proto, str) and proto.strip():
        return proto.strip().lower()
    caps = scan_result.get("protocol_capabilities")
    if isinstance(caps, dict):
        c_proto = caps.get("protocol_id")
        if isinstance(c_proto, str) and c_proto.strip() and c_proto.strip().lower() != "generic":
            return c_proto.strip().lower()
    b_proto = (scan_result.get("banner_info") or {}).get("protocol")
    if isinstance(b_proto, str) and b_proto.strip() and b_proto.strip().lower() not in ("generic", "tls"):
        return b_proto.strip().lower()
    return None


def _is_protocol_unsupported(scan_result):
    """
    Determine whether scan_result explicitly requested an unsupported protocol using
    capability metadata from scan_result or ProtocolRegistry (no hardcoded protocol allowlist).
    """
    if not isinstance(scan_result, dict):
        return False
    if scan_result.get("protocol_supported") is False:
        return True
    if scan_result.get("protocol_supported") is True:
        return False
    caps = scan_result.get("protocol_capabilities")
    if isinstance(caps, dict) and "supports_auth_calibration" in caps:
        return not bool(caps.get("supports_auth_calibration"))
    raw_proto = scan_result.get("protocol_id")
    if isinstance(raw_proto, str) and raw_proto.strip():
        proto_id = raw_proto.strip().lower()
        if _get_active_auth_summary(scan_result) is not None:
            return False
        reg = scan_result.get("_registry") or protocols.DEFAULT_REGISTRY
        adapter = reg.get_by_name(proto_id)
        return adapter is None or not getattr(adapter, "supports_auth_calibration", False)
    return False


def _get_auth_calibration_status(auth_dict):
    """
    Classify calibration status into:
    - 'NOT_REQUESTED': operator did not opt into authentication calibration
    - 'INVALID_CALIBRATION': unexpected successful authentication invalidated the run
    - 'UNAVAILABLE': calibration was requested by the operator but yielded 0 valid rejected probes
    - 'PARTIAL' / 'MEASURED': calibration yielded valid rejected probes
    """
    if not isinstance(auth_dict, dict) or not bool(auth_dict):
        return "NOT_REQUESTED"
    explicit_status = auth_dict.get("calibration_status")
    if explicit_status == "NOT_REQUESTED":
        return "NOT_REQUESTED"
    if explicit_status == "INVALID_CALIBRATION" or (auth_dict.get("successful_count") or 0) > 0:
        return "INVALID_CALIBRATION"

    has_session_or_probe_activity = (
        (auth_dict.get("session_count") or 0) > 0
        or (auth_dict.get("probe_attempt_count") or 0) > 0
        or (auth_dict.get("completed_count") or 0) > 0
        or (auth_dict.get("rejected_count") or 0) > 0
    )
    if explicit_status in ("UNAVAILABLE", "PARTIAL", "MEASURED"):
        return explicit_status
    if not has_session_or_probe_activity:
        return "NOT_REQUESTED"
    if _get_rejected_probe_count(auth_dict) == 0:
        return "UNAVAILABLE"
    return "MEASURED"


def _is_auth_calibration_requested(auth_dict):
    """
    Return True when the operator requested authentication calibration (even if session
    setup failed before any authentication probe could be transmitted).
    Returns False when calibration was not requested (e.g. None, {}, or NOT_REQUESTED).
    """
    return _get_auth_calibration_status(auth_dict) != "NOT_REQUESTED"


def _get_auth_probe_attempt_count(auth_dict):
    """
    Return the number of authentication requests actually initiated on the wire.
    Handshake/session setup failures before authentication produce 0 probe attempts.
    """
    if not isinstance(auth_dict, dict) or not _is_auth_calibration_requested(auth_dict):
        return 0
    if "probe_attempt_count" in auth_dict and auth_dict.get("probe_attempt_count") is not None:
        return int(auth_dict.get("probe_attempt_count") or 0)
    return int(auth_dict.get("completed_count") or 0)


def _is_auth_calibration_attempted(auth_dict):
    """
    Backward-compatible helper indicating whether authentication calibration was requested/active.
    Note: To check whether authentication requests were actually sent on the wire (as opposed to
    failing during pre-auth handshake), use _get_auth_probe_attempt_count(auth_dict) > 0.
    """
    return _is_auth_calibration_requested(auth_dict)


def _infer_auth_dict_protocol(scan_result, auth_dict):
    """
    Determine the protocol of auth_dict using:
    1. Explicit auth_dict.get("protocol") when present.
    2. Otherwise, infer from the matching protocol-specific key (<proto>_auth) in scan_result.
    Returns lowercase protocol string, '__conflicting__' if bound to multiple conflicting keys, or None.
    """
    if not isinstance(auth_dict, dict):
        return None
    explicit = auth_dict.get("protocol")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip().lower()
    if isinstance(scan_result, dict):
        matched_protos = [
            k[:-5].strip().lower()
            for k, v in scan_result.items()
            if k.endswith("_auth") and v is auth_dict and k[:-5].strip()
        ]
        unique_protos = set(matched_protos)
        if len(unique_protos) == 1:
            return matched_protos[0]
        if len(unique_protos) > 1:
            return "__conflicting__"
    return None


def _get_active_auth_summary(scan_result):
    """
    Return the active protocol's authentication calibration summary dict (if requested).
    Uses explicit auth_dict.protocol when present, otherwise infers from the matching
    protocol-specific key (<proto>_auth), and verifies consistency with the active protocol.
    On a mismatch, rejects the candidate so stale or conflicting calibration is never used.
    """
    if not isinstance(scan_result, dict):
        return None
    active_proto = _resolve_active_protocol(scan_result)
    if active_proto is not None:
        candidates = [
            scan_result.get(f"{active_proto}_auth"),
            scan_result.get("auth_calibration"),
        ]
    else:
        # Legacy test fixtures without explicit protocol_id or banner:
        # Discover any <proto>_auth dictionaries present and refuse to guess if more than one protocol is populated.
        proto_auth_dicts = [
            val for key, val in scan_result.items()
            if key.endswith("_auth") and _is_auth_calibration_requested(val)
        ]
        if len(proto_auth_dicts) > 1:
            return None
        candidates = [scan_result.get("auth_calibration")] + proto_auth_dicts

    for cand in candidates:
        if not _is_auth_calibration_requested(cand):
            continue
        cand_proto = _infer_auth_dict_protocol(scan_result, cand)
        if cand_proto == "__conflicting__":
            continue
        if active_proto and cand_proto and cand_proto != active_proto:
            continue
        return cand
    return None


def _get_rejected_probe_count(auth_dict):
    """
    Return the count of valid rejected authentication probes.
    Never mixes successful probes into rejected-probe timing counts.
    """
    if not isinstance(auth_dict, dict):
        return 0
    if (auth_dict.get("successful_count") or 0) > 0 or auth_dict.get("calibration_status") == "INVALID_CALIBRATION":
        return 0
    if "rejected_count" in auth_dict and auth_dict.get("rejected_count") is not None:
        return int(auth_dict.get("rejected_count") or 0)
    return int(auth_dict.get("completed_count") or 0)


def _assess_measurement_confidence(scan_result, has_proto, has_auth, k_srv_is_lower_bound, k_client, k_effective=1):
    """
    Classify measurement confidence transparently without inventing coverage guarantees.
    Accounts for sample counts, TCP/protocol/auth failures, timeouts, unverified reuse bounds,
    and effective cycle variability (preventing sub-10ms LAN TCP jitter from falsely degrading
    a multi-second authentication workload estimate when combined cycle CV is low).
    """
    n_succ = scan_result.get("success_count", 0)
    n_fail = scan_result.get("failure_count", 0)
    var_ind = scan_result.get("variability_indicator", "INDETERMINATE")
    proto_fails = scan_result.get("protocol_failure_count", 0)
    raw_auth = _get_active_auth_summary(scan_result)
    auth_requested = _is_auth_calibration_requested(raw_auth)
    auth_dict = raw_auth if auth_requested else {}
    auth_status = _get_auth_calibration_status(auth_dict) if auth_requested else "NOT_REQUESTED"
    probe_attempts = _get_auth_probe_attempt_count(auth_dict) if auth_requested else 0
    auth_timeouts = auth_dict.get("timeout_count", 0)
    auth_errors = auth_dict.get("error_count", 0)
    unexpected_sess_fails = auth_dict.get("unexpected_session_failure_count", 0)
    auth_rejected = _get_rejected_probe_count(auth_dict) if auth_requested else 0
    auth_succ_unexpected = auth_dict.get("successful_count", 0)

    k_eff = (
        k_effective
        if (not isinstance(k_effective, bool) and isinstance(k_effective, int) and k_effective >= 1)
        else 1
    )

    reasons = []
    if n_succ < 2:
        reasons.append("fewer than 2 successful TCP connections")
    if n_fail > 0:
        reasons.append(f"{n_fail} TCP connection failure(s) observed")

    effective_var_high = False
    effective_var_mod = False
    if has_auth and auth_rejected >= 1:
        tcp_mean_ms = scan_result.get("tcp_connect_mean_ms") or 0.0
        tcp_std_ms = scan_result.get("tcp_connect_std_ms") or 0.0
        proto_mean_ms = scan_result.get("protocol_overhead_mean_ms") or 0.0
        proto_std_ms = scan_result.get("protocol_overhead_std_ms") or 0.0
        auth_mean_ms = auth_dict.get("auth_mean_ms") or 0.0
        auth_std_ms = auth_dict.get("auth_std_ms") or 0.0
        cycle_mean_ms = (tcp_mean_ms + proto_mean_ms) / k_eff + auth_mean_ms
        cycle_std_ms = math.hypot(tcp_std_ms / k_eff, proto_std_ms / k_eff, auth_std_ms)
        cycle_cv = (cycle_std_ms / cycle_mean_ms) if cycle_mean_ms > 0 else 0.0
        if cycle_cv >= config.CV_MODERATE_THRESHOLD:
            effective_var_high = True
            reasons.append(f"high full-cycle timing variability (CV {cycle_cv * 100.0:.2f}% >= 35%)")
        elif cycle_cv >= config.CV_LOW_THRESHOLD:
            effective_var_mod = True
            reasons.append(f"moderate full-cycle timing variability (CV {cycle_cv * 100.0:.2f}%)")
        elif var_ind == "HIGH":
            reasons.append(
                f"high relative TCP handshake jitter (CV >= 35%), but negligible impact on full authentication cycle (combined CV {cycle_cv * 100.0:.2f}%)"
            )
    else:
        if var_ind == "HIGH":
            effective_var_high = True
            reasons.append("high TCP timing variability (CV >= 35%)")
        elif var_ind == "MODERATE":
            effective_var_mod = True
            reasons.append("moderate TCP timing variability")

    if proto_fails > 0:
        reasons.append(f"{proto_fails} protocol greeting/handshake failure(s)/timeout(s)")
    if auth_requested:
        if auth_status == "INVALID_CALIBRATION" or auth_succ_unexpected > 0:
            reasons.append(
                f"authentication calibration invalidated by unexpected successful authentication ({auth_succ_unexpected} probe(s) succeeded)"
            )
        elif probe_attempts == 0:
            reasons.append(
                "authentication calibration requested, but 0 authentication probes were sent (session/handshake setup failed before authentication)"
            )
        elif auth_rejected < 2:
            reasons.append("fewer than 2 completed rejected authentication probes")
        if auth_timeouts > 0 or auth_errors > 0 or unexpected_sess_fails > 0:
            reasons.append(
                f"unreliable auth session anomalies ({auth_timeouts} timeout(s), {auth_errors} error(s), "
                f"{unexpected_sess_fails} unexpected session drop(s)); failure penalties not extrapolated"
            )
        if k_srv_is_lower_bound and k_client is None:
            reasons.append("server connection reuse limit not reached during probing (lower bound only; client reuse unverified)")

    if (
        n_succ < 2
        or effective_var_high
        or n_fail > 0
        or proto_fails > 0
        or auth_timeouts > 0
        or auth_errors > 0
        or unexpected_sess_fails > 0
        or auth_succ_unexpected > 0
        or (auth_requested and (auth_status == "INVALID_CALIBRATION" or probe_attempts == 0 or auth_rejected < 2))
    ):
        level = "LOW"
    elif not has_proto:
        level = "LOW (TCP-Only Baseline)"
    elif not has_auth:
        level = "MODERATE (Setup Measured; Auth Unmeasured)" if not effective_var_mod else "LOW"
    elif effective_var_mod or (k_srv_is_lower_bound and k_client is None):
        level = "MODERATE"
    else:
        level = "HIGH"

    return {
        "confidence_level": level,
        "confidence_reasons": reasons if reasons else ["Consistent sample window with zero observed transport/protocol errors"],
    }


def calculate_feasibility(total_tries, speed=None, max_hours=config.DEFAULT_PLANNING_BUDGET_HOURS, *,
                          scan_result=None, mode="Dictionary_Audit", candidate_space_error=None,
                          observed_workload_seconds=None, client_attempts_per_conn=None):
    """
    Calculate network-only TCP connection planning rates, dynamic protocol-setup models,
    service-aware protocol authentication workload durations, target service speed/concurrency
    recommendations (-t 1 and -t N), and decision-support assessments.

    Never fabricates authentication throughput from bare unverified speeds or fixed port constants.
    Produces a Full Authentication Estimate ONLY when valid rejected authentication timing measurements exist.
    """
    if total_tries is not None and (
        isinstance(total_tries, bool) or not isinstance(total_tries, int) or total_tries < 0
    ):
        raise ValueError("total_tries must be a non-negative integer or None")
    if max_hours is not None and (
        isinstance(max_hours, bool) or not isinstance(max_hours, (int, float)) or not math.isfinite(max_hours) or max_hours <= 0
    ):
        raise ValueError("max_hours must be a finite positive number or None")
    if client_attempts_per_conn is not None and (
        isinstance(client_attempts_per_conn, bool)
        or not isinstance(client_attempts_per_conn, int)
        or client_attempts_per_conn < 1
    ):
        raise ValueError("client_attempts_per_conn must be a positive integer or None")

    # If called without a scan_result (e.g., standalone candidate-count check), return safe structure
    if not isinstance(scan_result, dict):
        return {
            "total_tries": total_tries,
            "network_model_rate_tcp_only_per_sec": None,
            "network_model_rate_paced_per_sec": None,
            "suggested_sequential_rate_per_sec": None,
            "suggested_parallel_tasks": None,
            "tcp_only_time_cost_seconds": None,
            "tcp_only_time_cost_minutes": None,
            "tcp_only_time_cost_hours": None,
            "tcp_only_time_cost_days": None,
            "paced_time_cost_seconds": None,
            "observed_range_min_seconds": None,
            "observed_range_max_seconds": None,
            "planning_budget_hours": max_hours,
            "within_network_budget": None,
            "evidence_level": "CANDIDATE COUNT ONLY",
            "model_assumptions": [
                "No TCP scan observations were supplied to calculate network connection time cost.",
            ],
        }

    evidence_origin = scan_result.get("evidence_origin", "measured")
    n_total = scan_result.get("attempt_count", 0)
    n_succ = scan_result.get("success_count", 0)
    n_fail = scan_result.get("failure_count", 0)
    mean_ms = scan_result.get("tcp_connect_mean_ms")
    min_ms = scan_result.get("tcp_connect_min_ms")
    max_ms = scan_result.get("tcp_connect_max_ms")
    std_ms = scan_result.get("tcp_connect_std_ms")
    pause_sec = scan_result.get("sampling", {}).get(
        "pause_between_attempts_seconds", config.PROBE_INTERVAL_SECONDS
    )

    mean_sec = (mean_ms / 1000.0) if (n_succ > 0 and mean_ms is not None and mean_ms > 0) else None
    min_sec = (min_ms / 1000.0) if (n_succ > 0 and min_ms is not None and min_ms >= 0) else None
    max_sec = (max_ms / 1000.0) if (n_succ > 0 and max_ms is not None and max_ms >= 0) else None
    std_sec = (std_ms / 1000.0) if (n_succ >= 2 and std_ms is not None and std_ms >= 0) else None

    tcp_only_rate = (1.0 / mean_sec) if mean_sec is not None else None
    paced_cycle_sec = (mean_sec + pause_sec) if mean_sec is not None else None
    paced_rate = (1.0 / paced_cycle_sec) if (paced_cycle_sec is not None and paced_cycle_sec > 0) else None

    # Dynamic Protocol Setup Overhead (strictly post-connect banner/greeting or SSH handshake arrival)
    proto_mean_ms = scan_result.get("protocol_overhead_mean_ms")
    proto_std_ms = scan_result.get("protocol_overhead_std_ms")
    proto_min_ms = scan_result.get("protocol_overhead_min_ms")
    proto_max_ms = scan_result.get("protocol_overhead_max_ms")
    proto_se_ms = scan_result.get("protocol_overhead_se_ms")
    proto_fails = scan_result.get("protocol_failure_count", 0)
    proto_mean_sec = (proto_mean_ms / 1000.0) if (proto_mean_ms is not None and proto_mean_ms >= 0) else None
    proto_std_sec = (proto_std_ms / 1000.0) if (proto_std_ms is not None and proto_std_ms >= 0) else None
    proto_min_sec = (proto_min_ms / 1000.0) if (proto_min_ms is not None and proto_min_ms >= 0) else None
    proto_max_sec = (proto_max_ms / 1000.0) if (proto_max_ms is not None and proto_max_ms >= 0) else None
    proto_se_sec = (proto_se_ms / 1000.0) if (proto_se_ms is not None and proto_se_ms >= 0) else None

    # Optional Protocol Authentication Timing & Empirical Session Reuse (protocol-matched)
    raw_auth = _get_active_auth_summary(scan_result)
    auth_requested = _is_auth_calibration_requested(raw_auth)
    auth_dict = raw_auth if auth_requested else None
    auth_cal_status = _get_auth_calibration_status(auth_dict) if auth_requested else "NOT_REQUESTED"
    auth_probe_attempts = _get_auth_probe_attempt_count(auth_dict) if auth_requested else 0
    is_invalid_cal = (auth_cal_status == "INVALID_CALIBRATION")
    auth_rejected_count = _get_rejected_probe_count(auth_dict) if (auth_requested and not is_invalid_cal) else 0
    auth_mean_ms = auth_dict.get("auth_mean_ms") if (auth_requested and not is_invalid_cal and auth_rejected_count > 0) else None
    auth_std_ms = auth_dict.get("auth_std_ms") if (auth_requested and not is_invalid_cal and auth_rejected_count > 0) else None
    auth_min_ms = auth_dict.get("auth_min_ms") if (auth_requested and not is_invalid_cal and auth_rejected_count > 0) else None
    auth_max_ms = auth_dict.get("auth_max_ms") if (auth_requested and not is_invalid_cal and auth_rejected_count > 0) else None
    auth_se_ms = auth_dict.get("auth_se_ms") if (auth_requested and not is_invalid_cal and auth_rejected_count > 0) else None
    disconnect_mean_ms = auth_dict.get("disconnect_detection_mean_ms") if (auth_requested and not is_invalid_cal) else None

    k_srv_exact = auth_dict.get("observed_server_reuse_limit") if (auth_requested and not is_invalid_cal) else None
    k_srv_lower_bound = auth_dict.get("observed_server_reuse_lower_bound") if (auth_requested and not is_invalid_cal) else None
    k_srv_is_lower_bound = bool(auth_dict.get("reuse_limit_is_lower_bound")) if (auth_requested and not is_invalid_cal) else False

    auth_mean_sec = (auth_mean_ms / 1000.0) if (auth_mean_ms is not None and auth_mean_ms > 0) else None
    auth_std_sec = (auth_std_ms / 1000.0) if (auth_std_ms is not None and auth_std_ms >= 0) else None
    auth_min_sec = (auth_min_ms / 1000.0) if (auth_min_ms is not None and auth_min_ms >= 0) else None
    auth_max_sec = (auth_max_ms / 1000.0) if (auth_max_ms is not None and auth_max_ms >= 0) else None
    auth_se_sec = (auth_se_ms / 1000.0) if (auth_se_ms is not None and auth_se_ms >= 0) else None
    disconnect_detect_sec = (
        (disconnect_mean_ms / 1000.0)
        if (disconnect_mean_ms is not None and disconnect_mean_ms >= 0 and k_srv_exact is not None)
        else 0.0
    )

    auth_proto = _infer_auth_dict_protocol(scan_result, auth_dict) if auth_dict is not None else None
    active_proto = _resolve_active_protocol(scan_result)
    if auth_proto == "__conflicting__" or (auth_proto and active_proto and auth_proto != active_proto):
        resolved_proto = None
    else:
        resolved_proto = auth_proto or active_proto
    proto_label = str(resolved_proto).upper() if resolved_proto else "UNKNOWN"
    conn_noun = "FTP control connection" if proto_label == "FTP" else (
        f"{proto_label} connection" if proto_label != "UNKNOWN" else "protocol connection"
    )

    # Separate server reuse capacity (K_srv) from client reuse behavior (K_client)
    k_client = client_attempts_per_conn
    unverified_assumptions = []
    if k_srv_exact is not None and k_client is not None:
        k_effective = min(k_srv_exact, k_client)
        reuse_policy_note = (
            f"Effective reuse K_eff={k_effective} attempts/conn (min of confirmed server limit "
            f"K_srv={k_srv_exact} and configured client limit K_client={k_client})."
        )
    elif k_srv_exact is not None and k_client is None:
        k_effective = k_srv_exact
        reuse_policy_note = (
            f"Confirmed server reuse limit K_srv={k_srv_exact} attempts/conn; assumes client reuses "
            f"connections up to K_srv (client behavior K_client not independently verified)."
        )
        unverified_assumptions.append(
            f"Assumes auditing client reuses each {conn_noun} up to the server-enforced limit (K_srv={k_srv_exact})."
        )
    elif k_srv_lower_bound is not None and k_client is not None:
        if k_client <= k_srv_lower_bound:
            k_effective = k_client
            reuse_policy_note = (
                f"Effective reuse K_eff={k_effective} attempts/conn (configured K_client={k_client} is within "
                f"verified server lower bound K_srv >= {k_srv_lower_bound})."
            )
        else:
            k_effective = k_srv_lower_bound
            reuse_policy_note = (
                f"Conservative lower bound K_eff={k_effective} attempts/conn used: server verified for at least "
                f"K_srv >= {k_srv_lower_bound} attempts/conn, whereas requested K_client={k_client} exceeds probed depth."
            )
            unverified_assumptions.append(
                f"Server reuse was only probed up to {k_srv_lower_bound} attempts without disconnect; actual server limit above {k_srv_lower_bound} is unverified."
            )
    elif k_srv_lower_bound is not None and k_client is None:
        k_effective = k_srv_lower_bound
        reuse_policy_note = (
            f"Server permitted at least K_srv >= {k_srv_lower_bound} attempts/conn without disconnect (lower bound only); "
            f"modeled with K_eff={k_effective}, but actual server limit and client reuse policy are unverified."
        )
        unverified_assumptions.append(
            f"Server connection reuse limit was not reached within {k_srv_lower_bound} probes (K_srv >= {k_srv_lower_bound} is a lower bound, not the exact limit), and client reuse behavior (K_client) is unverified."
        )
    elif k_client is not None:
        k_effective = k_client
        reuse_policy_note = (
            f"Configured client reuse K_client={k_client} attempts/conn (server session limit K_srv unmeasured)."
        )
        unverified_assumptions.append(
            f"Server session reuse capacity (K_srv) was not measured; assumes server permits K_client={k_client} attempts per connection."
        )
    else:
        k_effective = 1
        reuse_policy_note = "Default 1 connection per candidate (K_eff=1; no session reuse assumed)."

    tcp_only_sec = None
    paced_sec = None
    range_min_sec = None
    range_max_sec = None
    within_budget = None

    setup_only_sec = None
    setup_rate_per_sec = None
    full_workload_sec = None
    sample_projection_min_sec = None
    sample_projection_max_sec = None
    full_workload_se_sec = None
    effective_auth_rate_per_sec = None
    effective_auth_rate_per_min = None
    estimated_connections = None
    reconnect_transitions = None

    raw_proto_id = scan_result.get("protocol_id")
    unsupported_proto = _is_protocol_unsupported(scan_result)

    # Resolve effective post-TCP protocol setup timing across all modes
    eff_proto_mean_sec = proto_mean_sec
    eff_proto_std_sec = proto_std_sec
    eff_proto_min_sec = proto_min_sec
    eff_proto_max_sec = proto_max_sec
    eff_proto_se_sec = proto_se_sec
    if eff_proto_mean_sec is None and auth_requested and auth_dict and auth_dict.get("handshake_mean_ms") is not None:
        eff_proto_mean_sec = auth_dict["handshake_mean_ms"] / 1000.0
        if auth_dict.get("handshake_std_ms") is not None:
            eff_proto_std_sec = auth_dict["handshake_std_ms"] / 1000.0
        if auth_dict.get("handshake_min_ms") is not None:
            eff_proto_min_sec = auth_dict["handshake_min_ms"] / 1000.0
        if auth_dict.get("handshake_max_ms") is not None:
            eff_proto_max_sec = auth_dict["handshake_max_ms"] / 1000.0
        if auth_dict.get("handshake_se_ms") is not None:
            eff_proto_se_sec = auth_dict["handshake_se_ms"] / 1000.0

    if mean_sec is not None and eff_proto_mean_sec is not None and (mean_sec + eff_proto_mean_sec) > 0:
        setup_rate_per_sec = 1.0 / (mean_sec + eff_proto_mean_sec)

    # Calculate Target Service Speed & Parallel Task (-t N) Recommendations across all modes
    p_succ = (n_succ / n_total) if (n_total and n_total > 0) else 1.0
    tcp_sd_s = std_sec if std_sec is not None else 0.0
    proto_sd_s = eff_proto_std_sec if eff_proto_std_sec is not None else 0.0
    auth_sd_s = auth_std_sec if auth_std_sec is not None else 0.0

    suggested_seq_rate = None
    suggested_parallel_tasks = None
    suggested_auth_t1_sec = None
    suggested_auth_t1_min = None
    suggested_service_auth_sec = None
    suggested_service_auth_min = None
    mean_service_auth_sec = None
    mean_service_auth_min = None
    suggested_service_workload_sec = None
    mean_service_workload_sec = None
    service_target_range_min_sec = None
    service_target_range_max_sec = None

    has_valid_auth = (
        auth_mean_sec is not None
        and auth_rejected_count > 0
        and not is_invalid_cal
        and not unsupported_proto
    )

    if mean_sec is not None:
        if eff_proto_mean_sec is not None:
            setup_buffered_sec = (mean_sec + eff_proto_mean_sec) + math.hypot(tcp_sd_s, proto_sd_s)
        else:
            setup_buffered_sec = mean_sec + tcp_sd_s
        if setup_buffered_sec > 0:
            suggested_seq_rate = p_succ / setup_buffered_sec

        auth_timeouts = auth_dict.get("timeout_count", 0) if auth_dict else 0
        auth_errors = auth_dict.get("error_count", 0) if auth_dict else 0
        unexpected_sess_fails = auth_dict.get("unexpected_session_failure_count", 0) if auth_dict else 0
        has_anomalies = (
            n_fail > 0
            or proto_fails > 0
            or auth_timeouts > 0
            or auth_errors > 0
            or unexpected_sess_fails > 0
            or n_succ < 2
        )
        if has_anomalies:
            suggested_parallel_tasks = 1
        elif has_valid_auth:
            cycle_m_s = ((mean_sec + (eff_proto_mean_sec or 0.0)) / k_effective) + auth_mean_sec
            cycle_sd_s = math.hypot(tcp_sd_s / k_effective, proto_sd_s / k_effective, auth_sd_s)
            cycle_cv = (cycle_sd_s / cycle_m_s) if cycle_m_s > 0 else 0.0
            # Protocol-specific concurrency shaping:
            # For SSH, cryptographic key exchange (KEX) and OpenSSH MaxStartups (10:30:100)
            # constrain parallel unauthenticated handshakes when KEX overhead is heavy (>= 250ms).
            if proto_label == "SSH" and (eff_proto_mean_sec or 0.0) >= 0.250:
                suggested_parallel_tasks = 2 if cycle_cv < config.CV_MODERATE_THRESHOLD else 1
            elif cycle_cv < config.CV_LOW_THRESHOLD:
                suggested_parallel_tasks = 4
            elif cycle_cv < config.CV_MODERATE_THRESHOLD:
                suggested_parallel_tasks = 2
            else:
                suggested_parallel_tasks = 1
        else:
            var_ind = scan_result.get("variability_indicator", "INDETERMINATE")
            if var_ind == "LOW":
                suggested_parallel_tasks = 4
            elif var_ind == "MODERATE" or (var_ind == "HIGH" and (std_ms or 0.0) <= 15.0 and (mean_ms or 0.0) <= 20.0):
                suggested_parallel_tasks = 2
            else:
                suggested_parallel_tasks = 1

    if mean_sec is not None and total_tries is not None and mode != "RTT_Only":
        tcp_only_sec = total_tries * mean_sec
        paced_sec = (total_tries * mean_sec) + (max(0, total_tries - 1) * pause_sec)
        if min_sec is not None and max_sec is not None:
            range_min_sec = total_tries * min_sec
            range_max_sec = total_tries * max_sec

        estimated_connections = math.ceil(total_tries / k_effective) if total_tries > 0 else 0
        reconnect_transitions = max(0, estimated_connections - 1) if estimated_connections is not None else 0

        if eff_proto_mean_sec is not None:
            # Per-connection cost: 1 TCP handshake + 1 post-connect protocol greeting/handshake
            # Remains preserved and reported even if active authentication calibration is unavailable or invalid.
            conn_setup_sec = mean_sec + eff_proto_mean_sec
            setup_only_sec = estimated_connections * conn_setup_sec

            # Full Authentication Estimate is ONLY produced when valid rejected authentication timing measurements exist
            if has_valid_auth:
                # Per-connection costs: M * (TCP + protocol setup/handshake) + (M - 1) * server disconnect detection overhead
                # Per-candidate costs: C * (completed rejected authentication time)
                # Zero overlap between TCP connect, protocol setup/handshake, disconnect detection, and auth.
                total_conn_and_reconnect_sec = (
                    (estimated_connections * conn_setup_sec)
                    + (reconnect_transitions * disconnect_detect_sec)
                )
                total_auth_processing_sec = total_tries * auth_mean_sec
                full_workload_sec = total_conn_and_reconnect_sec + total_auth_processing_sec

                if full_workload_sec > 0 and total_tries > 0:
                    effective_auth_rate_per_sec = total_tries / full_workload_sec
                    effective_auth_rate_per_min = effective_auth_rate_per_sec * 60.0

                if min_sec is not None and eff_proto_min_sec is not None and auth_min_sec is not None:
                    sample_projection_min_sec = (
                        estimated_connections * (min_sec + eff_proto_min_sec)
                        + (reconnect_transitions * disconnect_detect_sec)
                        + (total_tries * auth_min_sec)
                    )
                if max_sec is not None and eff_proto_max_sec is not None and auth_max_sec is not None:
                    sample_projection_max_sec = (
                        estimated_connections * (max_sec + eff_proto_max_sec)
                        + (reconnect_transitions * disconnect_detect_sec)
                        + (total_tries * auth_max_sec)
                    )
                tcp_se_sec = (std_sec / (n_succ ** 0.5)) if (std_sec is not None and n_succ >= 2) else 0.0
                p_se = eff_proto_se_sec if eff_proto_se_sec is not None else 0.0
                a_se = auth_se_sec if auth_se_sec is not None else 0.0
                if tcp_se_sec > 0 or p_se > 0 or a_se > 0:
                    full_workload_se_sec = math.sqrt(
                        (estimated_connections ** 2) * (tcp_se_sec ** 2 + p_se ** 2)
                        + (total_tries ** 2) * (a_se ** 2)
                    )

        if max_hours is not None:
            if unsupported_proto or (auth_requested and full_workload_sec is None):
                # Never downgrade a failed/invalidated/unsupported full-authentication request
                # into a misleading TCP-only budget pass.
                within_budget = None
            else:
                primary_sec = full_workload_sec if full_workload_sec is not None else (
                    setup_only_sec if setup_only_sec is not None else tcp_only_sec
                )
                within_budget = primary_sec <= (max_hours * 3600.0)

    if mean_sec is not None and has_valid_auth:
        base_cycle_sec = (
            (full_workload_sec / total_tries)
            if (full_workload_sec is not None and total_tries and total_tries > 0)
            else (((mean_sec + (eff_proto_mean_sec or 0.0)) / k_effective) + auth_mean_sec)
        )
        cycle_sd_s = math.hypot(tcp_sd_s / k_effective, proto_sd_s / k_effective, auth_sd_s)
        buffered_cycle_sec = base_cycle_sec + cycle_sd_s
        if buffered_cycle_sec > 0:
            suggested_auth_t1_sec = p_succ / buffered_cycle_sec
            suggested_auth_t1_min = suggested_auth_t1_sec * 60.0
            n_tasks = suggested_parallel_tasks or 1
            raw_target_auth_sec = n_tasks * suggested_auth_t1_sec
            if suggested_seq_rate is not None:
                raw_target_auth_sec = min(raw_target_auth_sec, suggested_seq_rate * k_effective)
            suggested_service_auth_sec = raw_target_auth_sec
            suggested_service_auth_min = suggested_service_auth_sec * 60.0

            mean_t1_sec = effective_auth_rate_per_sec if effective_auth_rate_per_sec is not None else (p_succ / base_cycle_sec)
            raw_mean_target_sec = n_tasks * mean_t1_sec
            if setup_rate_per_sec is not None:
                raw_mean_target_sec = min(raw_mean_target_sec, setup_rate_per_sec * k_effective)
            mean_service_auth_sec = raw_mean_target_sec
            mean_service_auth_min = mean_service_auth_sec * 60.0

            if total_tries is not None and mode != "RTT_Only" and suggested_service_auth_sec > 0:
                suggested_service_workload_sec = total_tries / suggested_service_auth_sec
            if total_tries is not None and mode != "RTT_Only" and mean_service_auth_sec and mean_service_auth_sec > 0:
                mean_service_workload_sec = total_tries / mean_service_auth_sec
            if sample_projection_min_sec is not None and sample_projection_max_sec is not None and n_tasks > 0:
                service_target_range_min_sec = sample_projection_min_sec / n_tasks
                service_target_range_max_sec = sample_projection_max_sec / n_tasks

    insufficient_planning_data = bool(
        mode != "RTT_Only"
        and total_tries is not None
        and (unsupported_proto or (auth_requested and full_workload_sec is None))
    )

    # Validate active prediction (prefer full_workload_sec when measured, else tcp_only_sec)
    validation = None
    pred_for_val = full_workload_sec if (full_workload_sec is not None and full_workload_sec > 0) else tcp_only_sec
    bounds_for_val = (
        (sample_projection_min_sec, sample_projection_max_sec)
        if (full_workload_sec is not None and sample_projection_min_sec is not None and sample_projection_max_sec is not None)
        else (range_min_sec, range_max_sec)
    )
    if observed_workload_seconds is not None and pred_for_val is not None and pred_for_val > 0:
        validation = evaluate_workload_prediction(
            pred_for_val,
            observed_workload_seconds,
            bounds_for_val,
        )

    if evidence_origin == "synthetic":
        evidence_level = "SYNTHETIC / DEMONSTRATION ONLY"
    elif n_succ == 0 or tcp_only_rate is None:
        evidence_level = "MEASURED ONLY"
    elif validation is not None:
        evidence_level = "MEASURED + VALIDATED MODEL ESTIMATE"
    else:
        evidence_level = "MEASURED + MODEL ESTIMATE"

    confidence = _assess_measurement_confidence(
        scan_result,
        has_proto=(proto_mean_sec is not None or (auth_requested and auth_dict.get("handshake_mean_ms") is not None)),
        has_auth=has_valid_auth,
        k_srv_is_lower_bound=k_srv_is_lower_bound,
        k_client=k_client,
        k_effective=k_effective,
    )

    decisions = _derive_planning_conclusions(
        scan_result=scan_result,
        mode=mode,
        total_tries=total_tries,
        tcp_only_sec=tcp_only_sec,
        paced_sec=paced_sec,
        budget_hours=max_hours,
        candidate_space_error=candidate_space_error,
    )

    assumptions = [
        "Scenario models 1 fresh sequential TCP connection per candidate (no connection reuse or concurrency).",
        "tcp_only_time_cost_seconds = total_tries * mean_tcp_connect_seconds (cumulative socket.connect() establishment only).",
        f"paced_time_cost_seconds adds the configured {pause_sec * 1000:.0f} ms inter-attempt pause between sequential connections.",
        "Excludes protocol banner exchange, TLS/SSH key exchange, credential transmission, server password verification, and account lockout delays.",
        "Candidate count does not necessarily equal TCP connection count if a protocol reuses sessions or enforces multi-attempt channels.",
    ]
    if proto_mean_sec is not None or (auth_requested and auth_dict.get("handshake_mean_ms") is not None):
        assumptions.append(
            "protocol_adjusted_time_cost_seconds dynamically adds measured post-connect greeting/handshake overhead per connection without double-counting socket.connect()."
        )
    if has_valid_auth:
        caps = scan_result.get("protocol_capabilities") or {}
        reg = scan_result.get("_registry") or protocols.DEFAULT_REGISTRY
        reg_adapter = reg.get_by_name(resolved_proto) if resolved_proto else None
        if proto_label == "FTP":
            setup_stage_desc = "220 greeting"
            auth_stage_desc = "failed USER/PASS auth"
        elif proto_label == "SSH":
            setup_stage_desc = "SSH handshake"
            auth_stage_desc = "rejected SSH userauth"
        else:
            setup_stage_desc = caps.get("setup_stage_label") or getattr(reg_adapter, "setup_stage_label", "protocol greeting")
            auth_stage_desc = caps.get("auth_stage_label") or getattr(reg_adapter, "auth_stage_label", f"rejected {proto_label} auth")
        assumptions.append(
            f"full_workload_time_cost_seconds separates per-connection costs (M={estimated_connections} connections * (TCP + {setup_stage_desc}) + "
            f"{reconnect_transitions} reconnect disconnect-detection transitions) from per-candidate costs (C={total_tries} * {auth_stage_desc})."
        )
        assumptions.append(
            "sample_based_projection_range_[min|max]_seconds scales the observed sample extremes linearly; it is not a worst-case bound or validated statistical prediction interval."
        )
        assumptions.extend(unverified_assumptions)

    result = {
        "total_tries": total_tries,
        "network_model_rate_tcp_only_per_sec": tcp_only_rate,
        "network_model_rate_paced_per_sec": paced_rate,
        "suggested_sequential_rate_per_sec": suggested_seq_rate,
        "suggested_parallel_tasks": suggested_parallel_tasks,
        "tcp_only_time_cost_seconds": tcp_only_sec,
        "tcp_only_time_cost_minutes": (tcp_only_sec / 60.0) if tcp_only_sec is not None else None,
        "tcp_only_time_cost_hours": (tcp_only_sec / 3600.0) if tcp_only_sec is not None else None,
        "tcp_only_time_cost_days": (tcp_only_sec / 86400.0) if tcp_only_sec is not None else None,
        "tcp_only_time_cost_human": format_duration(tcp_only_sec),
        "paced_time_cost_seconds": paced_sec,
        "paced_time_cost_human": format_duration(paced_sec),
        "observed_range_min_seconds": range_min_sec,
        "observed_range_max_seconds": range_max_sec,
        "planning_budget_hours": max_hours,
        "planning_budget_seconds": (max_hours * 3600.0) if max_hours is not None else None,
        "within_network_budget": within_budget,
        "planning_assessment": decisions["planning_assessment"],
        "red_team_guidance": decisions["red_team_guidance"],
        "blue_team_guidance": decisions["blue_team_guidance"],
        "variability_recommendation": decisions["variability_recommendation"],
        "evidence_level": evidence_level,
        "workload_validation": validation,
        "model_assumptions": assumptions,
    }

    if (
        proto_mean_sec is not None
        or auth_requested
        or client_attempts_per_conn is not None
        or unsupported_proto
    ):
        result.update({
            "protocol_setup_rate_per_sec": setup_rate_per_sec,
            "protocol_adjusted_time_cost_seconds": setup_only_sec,
            "protocol_adjusted_time_cost_human": format_duration(setup_only_sec),
            "observed_server_reuse_limit": k_srv_exact,
            "observed_server_reuse_lower_bound": k_srv_lower_bound,
            "reuse_limit_is_lower_bound": k_srv_is_lower_bound,
            "configured_client_reuse_limit": k_client,
            "effective_attempts_per_connection": k_effective,
            "connection_reuse_policy": reuse_policy_note,
            "unverified_assumptions": unverified_assumptions,
            "estimated_connections_required": estimated_connections,
            "disconnect_detection_overhead_per_reconnect_seconds": disconnect_detect_sec,
            "full_workload_time_cost_seconds": full_workload_sec,
            "full_workload_time_cost_human": format_duration(full_workload_sec),
            "sample_based_projection_range_min_seconds": sample_projection_min_sec,
            "sample_based_projection_range_max_seconds": sample_projection_max_sec,
            "full_workload_propagated_se_seconds": full_workload_se_sec,
            "effective_auth_rate_per_sec": effective_auth_rate_per_sec,
            "effective_auth_rate_per_min": effective_auth_rate_per_min,
            "suggested_auth_rate_t1_per_sec": suggested_auth_t1_sec,
            "suggested_auth_rate_t1_per_min": suggested_auth_t1_min,
            "suggested_service_auth_rate_per_sec": suggested_service_auth_sec,
            "suggested_service_auth_rate_per_min": suggested_service_auth_min,
            "mean_service_auth_rate_per_sec": mean_service_auth_sec,
            "mean_service_auth_rate_per_min": mean_service_auth_min,
            "suggested_service_workload_seconds": suggested_service_workload_sec,
            "suggested_service_workload_human": format_duration(suggested_service_workload_sec),
            "mean_service_workload_seconds": mean_service_workload_sec,
            "mean_service_workload_human": format_duration(mean_service_workload_sec),
            "service_target_range_min_seconds": service_target_range_min_sec,
            "service_target_range_max_seconds": service_target_range_max_sec,
            "auth_calibration_status": auth_cal_status if auth_requested else ("UNSUPPORTED_PROTOCOL" if unsupported_proto else None),
            "auth_probe_attempt_count": auth_probe_attempts if auth_requested else 0,
            "auth_failure_summary": auth_dict.get("failure_summary") if auth_requested else (
                (scan_result.get("unsupported_protocol_reason") or f"Protocol '{raw_proto_id}' does not have a registered timing adapter")
                if unsupported_proto else None
            ),
            "insufficient_planning_data": insufficient_planning_data,
            "measurement_confidence": "LOW" if unsupported_proto else confidence["confidence_level"],
            "measurement_confidence_reasons": (
                [f"unsupported protocol '{raw_proto_id}' (no registered timing adapter)"] + confidence["confidence_reasons"]
                if unsupported_proto
                else confidence["confidence_reasons"]
            ),
        })

    return result
