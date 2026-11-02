# protocols/ftp_adapter.py
# FTP Protocol Adapter (RFC 959) for dynamic 220 greeting setup timing and controlled USER/PASS calibration.

import errno
import socket
import time

import config
from protocols.base import ProtocolAdapter


def read_ftp_response(s):
    """
    Read a complete single-line or multi-line FTP response (RFC 959).
    Waits for newline-terminated lines before evaluating single-line ('XYZ ')
    or multi-line ('XYZ-' ... 'XYZ ') completion.
    Returns (status_code_str, first_line_str, full_response_str).
    """
    buffer = ""
    expected_end_prefix = None
    while True:
        chunk = s.recv(1024)
        if not chunk:
            break
        buffer += chunk.decode("utf-8", errors="replace")
        if "\n" not in buffer:
            continue
        complete_part = buffer if buffer.endswith("\n") else buffer.rsplit("\n", 1)[0] + "\n"
        lines = [line.strip("\r") for line in complete_part.splitlines() if line.strip("\r")]
        if not lines:
            continue
        first = lines[0]
        if expected_end_prefix is None and len(first) >= 4 and first[:3].isdigit():
            if first[3] == "-":
                expected_end_prefix = first[:3] + " "
            elif first[3] == " ":
                return first[:3], first.strip(), buffer.strip()
        if expected_end_prefix is not None:
            for line in lines[1:]:
                if line.startswith(expected_end_prefix):
                    return first[:3], first.strip(), buffer.strip()
        if buffer.endswith("\n") and expected_end_prefix is None:
            return first[:3] if len(first) >= 3 and first[:3].isdigit() else None, first.strip(), buffer.strip()
    lines = [line.strip() for line in buffer.splitlines() if line.strip()]
    first = lines[0] if lines else ""
    code = first[:3] if len(first) >= 3 and first[:3].isdigit() else None
    return code, first, buffer.strip()


class FTPAdapter(ProtocolAdapter):
    """
    Protocol Adapter for File Transfer Protocol (FTP, RFC 959).
    Measures post-TCP 220 service greeting overhead and explicitly authorized
    USER/PASS failed-authentication timing and server session-reuse limits.
    """

    protocol_id = "ftp"
    display_name = "FTP"
    default_ports = (21,)
    supports_passive_greeting = True
    supports_auth_calibration = True
    combines_setup_and_auth_session = False
    setup_stage_label = "Post-TCP Greeting"
    auth_stage_label = "failed USER/PASS auth"

    def matches_banner(self, banner):
        if not banner or not isinstance(banner, str):
            return False
        text = banner.strip()
        lower = text.lower()
        if "smtp" in lower:
            return False
        return "ftp" in lower and (
            text.startswith("220 ")
            or text.startswith("220-")
            or (len(text) >= 3 and text[:3].isdigit())
        )

    def measure_setup(self, sock, target_ip, port, timeout_seconds=None, clock_fn=None, **kwargs):
        if clock_fn is None:
            clock_fn = time.perf_counter
        start = clock_fn()
        try:
            code, first_line, _ = read_ftp_response(sock)
            elapsed = clock_fn() - start
            if first_line:
                return first_line, {
                    "status": "received",
                    "display": first_line,
                    "raw_banner": first_line,
                    "status_code": code,
                    "protocol": self.protocol_id,
                    "protocol_overhead_seconds": elapsed,
                    "explanation": "Service banner read from TCP connection.",
                }, elapsed, "success"
            return "Not Detected", {
                "status": "empty_response",
                "display": "Not Detected",
                "raw_banner": None,
                "protocol": self.protocol_id,
                "protocol_overhead_seconds": elapsed,
                "explanation": "TCP connection succeeded, but remote service closed stream or sent no initial bytes.",
            }, elapsed, "empty_response"
        except socket.timeout:
            elapsed = clock_fn() - start
            return "Not Detected", {
                "status": "timeout",
                "display": "Not Detected",
                "raw_banner": None,
                "protocol": self.protocol_id,
                "protocol_overhead_seconds": elapsed,
                "explanation": "TCP connection succeeded, but no banner bytes arrived before the socket read timeout.",
            }, elapsed, "timeout"
        except OSError as exc:
            elapsed = clock_fn() - start
            return "Not Detected", {
                "status": "connection_error",
                "display": "Not Detected",
                "raw_banner": None,
                "protocol": self.protocol_id,
                "protocol_overhead_seconds": elapsed,
                "explanation": f"TCP connection succeeded, but banner read raised {type(exc).__name__}: {exc}",
            }, elapsed, "error"

    def measure_auth_session(self, sock, username=None, reject_token=None, max_reuse_probes=None,
                             auth_timeout_seconds=None, authorize_auth_probes=False, clock_fn=None, **kwargs):
        """
        Execute an explicitly authorized FTP authentication probe sequence on an open FTP socket
        after the 220 service greeting has been consumed.
        Requires authorize_auth_probes=True explicitly; missing authorization never enables probes.
        If username is None, defaults to config.DEFAULT_CALIBRATION_USER.
        """
        if clock_fn is None:
            clock_fn = time.perf_counter
        if username is None:
            username = config.DEFAULT_CALIBRATION_USER
        if not isinstance(username, str) or not username.strip():
            raise ValueError("An explicit authorized FTP test username is required")
        if not authorize_auth_probes:
            raise ValueError("Active FTP authentication probes require authorize_auth_probes=True")
        if reject_token is None:
            reject_token = config.FTP_PROBE_REJECT_TOKEN
        if max_reuse_probes is None:
            max_reuse_probes = config.FTP_MAX_REUSE_PROBES
        if isinstance(max_reuse_probes, bool) or not isinstance(max_reuse_probes, int) or max_reuse_probes < 1:
            raise ValueError("max_reuse_probes must be a positive integer")
        if auth_timeout_seconds is None:
            auth_timeout_seconds = config.FTP_AUTH_TIMEOUT
        if (
            isinstance(auth_timeout_seconds, bool)
            or not isinstance(auth_timeout_seconds, (int, float))
            or auth_timeout_seconds <= 0
        ):
            raise ValueError("auth_timeout_seconds must be a positive number")

        clean_user = username.strip()
        probe_records = []
        completed_in_session = 0
        closed_by_server = False
        termination_reason = "probe_cap_reached"
        disconnect_detection_sec = None

        has_gettimeout = hasattr(sock, "gettimeout")
        prev_timeout = sock.gettimeout() if has_gettimeout else None
        if hasattr(sock, "settimeout"):
            sock.settimeout(auth_timeout_seconds)

        try:
            for seq in range(1, max_reuse_probes + 1):
                rec = {
                    "sequence_in_connection": seq,
                    "outcome": None,
                    "user_cmd_seconds": None,
                    "pass_cmd_seconds": None,
                    "auth_total_seconds": None,
                    "user_status_code": None,
                    "pass_status_code": None,
                    "server_closed_after": False,
                    "error": None,
                }
                t_auth_start = clock_fn()
                try:
                    t_u0 = clock_fn()
                    sock.sendall(f"USER {clean_user}\r\n".encode("utf-8"))
                    u_code, u_line, _ = read_ftp_response(sock)
                    t_u1 = clock_fn()
                    rec["user_cmd_seconds"] = t_u1 - t_u0
                    rec["user_status_code"] = u_code

                    if not u_line or u_code == "421":
                        elapsed_close = clock_fn() - t_auth_start
                        rec["outcome"] = "connection_closed"
                        rec["auth_total_seconds"] = elapsed_close
                        rec["server_closed_after"] = True
                        rec["error"] = u_line if u_line else "Server closed stream on USER command"
                        # Servers such as vsFTPd close the control stream right after the Nth 530
                        # rejection (returning EOF or 421 on the subsequent USER command).
                        if seq > 1 and (u_code == "421" or completed_in_session > 0):
                            termination_reason = "server_limit_after_auth"
                            disconnect_detection_sec = elapsed_close
                        else:
                            termination_reason = "mid_exchange_disconnect"
                            probe_records.append(rec)
                        closed_by_server = True
                        break

                    if u_code == "331":
                        t_p0 = clock_fn()
                        sock.sendall(f"PASS {reject_token}_{seq}\r\n".encode("utf-8"))
                        p_code, p_line, _ = read_ftp_response(sock)
                        t_p1 = clock_fn()
                        rec["pass_cmd_seconds"] = t_p1 - t_p0
                        rec["pass_status_code"] = p_code
                        rec["auth_total_seconds"] = t_p1 - t_auth_start
                        if p_code == "530":
                            rec["outcome"] = "rejected"
                            completed_in_session += 1
                        elif p_code == "230":
                            rec["outcome"] = "successful"
                            rec["error"] = f"Unexpected successful authentication (230): {p_line}"
                            termination_reason = "unexpected_auth_success"
                            probe_records.append(rec)
                            break
                        elif not p_line or p_code == "421":
                            rec["outcome"] = "connection_closed"
                            rec["server_closed_after"] = True
                            rec["error"] = p_line if p_line else "Server closed stream during PASS response"
                            termination_reason = "mid_exchange_disconnect"
                            probe_records.append(rec)
                            closed_by_server = True
                            break
                        elif p_code == "332":
                            rec["outcome"] = "error"
                            rec["error"] = f"Account restriction / ACCT required (332): {p_line}"
                            termination_reason = "account_restriction"
                            probe_records.append(rec)
                            break
                        else:
                            rec["outcome"] = "error"
                            rec["error"] = f"Unexpected PASS response: {p_line}"
                            termination_reason = "protocol_error"
                            probe_records.append(rec)
                            break
                    elif u_code == "530":
                        rec["pass_cmd_seconds"] = 0.0
                        rec["auth_total_seconds"] = t_u1 - t_auth_start
                        rec["outcome"] = "rejected"
                        completed_in_session += 1
                    elif u_code == "230":
                        rec["pass_cmd_seconds"] = 0.0
                        rec["auth_total_seconds"] = t_u1 - t_auth_start
                        rec["outcome"] = "successful"
                        rec["error"] = f"Unexpected successful authentication on USER (230): {u_line}"
                        termination_reason = "unexpected_auth_success"
                        probe_records.append(rec)
                        break
                    elif u_code == "332":
                        rec["auth_total_seconds"] = t_u1 - t_auth_start
                        rec["outcome"] = "error"
                        rec["error"] = f"Account restriction / ACCT required (332): {u_line}"
                        termination_reason = "account_restriction"
                        probe_records.append(rec)
                        break
                    else:
                        rec["auth_total_seconds"] = t_u1 - t_auth_start
                        rec["outcome"] = "error"
                        rec["error"] = f"Unexpected USER response: {u_line}"
                        termination_reason = "protocol_error"
                        probe_records.append(rec)
                        break
                except socket.timeout:
                    rec["auth_total_seconds"] = clock_fn() - t_auth_start
                    rec["outcome"] = "timeout"
                    stage_label = "USER" if rec["user_cmd_seconds"] is None else "PASS"
                    rec["error"] = (
                        f"Socket timeout ({auth_timeout_seconds:g}s) while awaiting FTP {stage_label} response"
                    )
                    termination_reason = "timeout"
                    probe_records.append(rec)
                    break
                except OSError as exc:
                    elapsed_err = clock_fn() - t_auth_start
                    rec["auth_total_seconds"] = elapsed_err
                    is_conn_reset = isinstance(exc, ConnectionError) or getattr(exc, "errno", None) in (
                        errno.ECONNRESET,
                        errno.EPIPE,
                        errno.ECONNABORTED,
                    )
                    if is_conn_reset and seq > 1 and completed_in_session > 0 and rec["user_status_code"] is None:
                        termination_reason = "server_limit_after_auth"
                        disconnect_detection_sec = elapsed_err
                        closed_by_server = True
                        break
                    rec["outcome"] = "connection_closed" if is_conn_reset else "error"
                    rec["server_closed_after"] = False
                    rec["error"] = f"{type(exc).__name__}: {exc}"
                    termination_reason = "mid_exchange_disconnect" if is_conn_reset else "transport_error"
                    probe_records.append(rec)
                    break

                probe_records.append(rec)

            try:
                sock.sendall(b"QUIT\r\n")
            except OSError:
                pass
        finally:
            if has_gettimeout and hasattr(sock, "settimeout"):
                try:
                    sock.settimeout(prev_timeout)
                except OSError:
                    pass

        return {
            "protocol": self.protocol_id,
            "completed_attempts_in_connection": completed_in_session,
            "server_closed_connection": closed_by_server,
            "termination_reason": termination_reason,
            "reuse_limit_is_lower_bound": (termination_reason == "probe_cap_reached" and completed_in_session > 0),
            "disconnect_detection_seconds": disconnect_detection_sec,
            "max_reuse_probes_tested": max_reuse_probes,
            "auth_timeout_seconds": auth_timeout_seconds,
            "probes": probe_records,
        }
