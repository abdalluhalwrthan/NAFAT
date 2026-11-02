# protocols/ssh_adapter.py
# SSH Protocol Adapter (RFC 4252 / RFC 4253) for passive banner observation,
# dynamic post-TCP cryptographic handshake timing, and controlled failed-authentication calibration.

import errno
import hashlib
import logging
import os
import socket
import time

try:
    import paramiko
except ImportError:
    paramiko = None  # Passive TCP/FTP and SSH banner observation need no SSH dependency.

import config
from protocols.base import ProtocolAdapter


class _LegacySSHHostKey:
    """
    Wire-format SSH host key wrapper supporting SHA-1 ssh-rsa and ssh-dss verification
    across Paramiko 2.x, 3.x, 4.x, and 5.0+ (where SHA-1 RSA and DSA were removed).
    """

    def __init__(self, msg=None, data=None, expected_type="ssh-rsa"):
        self._expected_type = expected_type
        if msg is None and data is not None and paramiko is not None and hasattr(paramiko, "Message"):
            msg = paramiko.Message(data)
        raw_bytes = msg.asbytes() if hasattr(msg, "asbytes") else (bytes(data) if data is not None else b"")
        self._raw = raw_bytes
        parse_msg = paramiko.Message(raw_bytes) if (paramiko is not None and hasattr(paramiko, "Message")) else msg
        key_type = parse_msg.get_text() if parse_msg is not None else expected_type
        self._key_type = key_type or expected_type
        self.key = None
        if self._key_type == "ssh-rsa":
            from cryptography.hazmat.primitives.asymmetric import rsa
            e = parse_msg.get_mpint()
            n = parse_msg.get_mpint()
            self.key = rsa.RSAPublicNumbers(e, n).public_key()
        elif self._key_type == "ssh-dss":
            from cryptography.hazmat.primitives.asymmetric import dsa
            p = parse_msg.get_mpint()
            q = parse_msg.get_mpint()
            g = parse_msg.get_mpint()
            y = parse_msg.get_mpint()
            self.key = dsa.DSAPublicNumbers(y, dsa.DSAParameterNumbers(p, q, g)).public_key()

    def get_name(self):
        return self._key_type

    def asbytes(self):
        return self._raw

    def __bytes__(self):
        return self._raw

    def __eq__(self, other):
        if hasattr(other, "get_name") and hasattr(other, "asbytes"):
            return self.get_name() == other.get_name() and self.asbytes() == other.asbytes()
        return False

    def verify_ssh_sig(self, data, msg):
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

            raw_sig = msg.asbytes() if hasattr(msg, "asbytes") else bytes(msg)
            sig_msg = paramiko.Message(raw_sig) if (paramiko is not None and hasattr(paramiko, "Message")) else msg
            sig_algo = sig_msg.get_text()
            sig_bytes = sig_msg.get_binary()

            if self._key_type == "ssh-rsa":
                hash_map = {
                    "ssh-rsa": hashes.SHA1(),
                    "rsa-sha2-256": hashes.SHA256(),
                    "rsa-sha2-512": hashes.SHA512(),
                }
                h_alg = hash_map.get(sig_algo)
                if h_alg is None or self.key is None:
                    return False
                self.key.verify(sig_bytes, data, padding.PKCS1v15(), h_alg)
                return True

            if self._key_type == "ssh-dss" and sig_algo == "ssh-dss":
                if self.key is None or len(sig_bytes) != 40:
                    return False
                r = int.from_bytes(sig_bytes[:20], "big")
                s = int.from_bytes(sig_bytes[20:40], "big")
                der_sig = encode_dss_signature(r, s)
                self.key.verify(der_sig, data, hashes.SHA1())
                return True
        except Exception:
            return False
        return False


def _make_legacy_rsa_key(msg=None, data=None):
    return _LegacySSHHostKey(msg=msg, data=data, expected_type="ssh-rsa")


def _make_legacy_dss_key(msg=None, data=None):
    return _LegacySSHHostKey(msg=msg, data=data, expected_type="ssh-dss")


def _ensure_paramiko_legacy_algorithms(transport):
    """
    Ensure legacy KEX and host-key algorithms (ssh-rsa, ssh-dss, DH SHA-1, and 1024-bit GEX)
    are registered and enabled on the Paramiko Transport instance across Paramiko 2.x-5.x+.
    Also suppresses Paramiko internal thread traceback logging to stderr.
    """
    try:
        p_log = logging.getLogger("paramiko.transport")
        p_log.setLevel(logging.CRITICAL + 1)
        p_log.propagate = False
        if hasattr(transport, "logger") and transport.logger is not None:
            transport.logger.setLevel(logging.CRITICAL + 1)
            transport.logger.propagate = False
    except Exception:
        pass

    if hasattr(transport, "disabled_algorithms"):
        transport.disabled_algorithms = {}

    try:
        kex_info = getattr(paramiko.Transport, "_kex_info", None)
        if isinstance(kex_info, dict):
            gex_sha256 = kex_info.get("diffie-hellman-group-exchange-sha256")
            if gex_sha256 is not None:
                try:
                    gex_sha256.min_bits = 1024
                except Exception:
                    pass
                if "diffie-hellman-group-exchange-sha1" not in kex_info and isinstance(gex_sha256, type):
                    class _LegacyKexGexSHA1(gex_sha256):
                        name = "diffie-hellman-group-exchange-sha1"
                        hash_algo = hashlib.sha1
                        min_bits = 1024
                    kex_info["diffie-hellman-group-exchange-sha1"] = _LegacyKexGexSHA1

            g14_sha256 = kex_info.get("diffie-hellman-group14-sha256")
            if g14_sha256 is not None and isinstance(g14_sha256, type):
                if "diffie-hellman-group14-sha1" not in kex_info:
                    class _LegacyKexGroup14SHA1(g14_sha256):
                        name = "diffie-hellman-group14-sha1"
                        hash_algo = hashlib.sha1
                    kex_info["diffie-hellman-group14-sha1"] = _LegacyKexGroup14SHA1
                if "diffie-hellman-group1-sha1" not in kex_info:
                    class _LegacyKexGroup1SHA1(g14_sha256):
                        name = "diffie-hellman-group1-sha1"
                        hash_algo = hashlib.sha1
                        P = int(
                            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
                            "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
                            "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
                            16,
                        )
                        G = 2
                    kex_info["diffie-hellman-group1-sha1"] = _LegacyKexGroup1SHA1

        key_info = getattr(paramiko.Transport, "_key_info", None)
        if isinstance(key_info, dict):
            key_info["ssh-rsa"] = _make_legacy_rsa_key
            if "ssh-dss" not in key_info:
                key_info["ssh-dss"] = _make_legacy_dss_key
        t_key_info = getattr(transport, "_key_info", None)
        if isinstance(t_key_info, dict):
            t_key_info["ssh-rsa"] = _make_legacy_rsa_key
            if "ssh-dss" not in t_key_info:
                t_key_info["ssh-dss"] = _make_legacy_dss_key

    except Exception:
        pass

    try:
        cur_kex = list(getattr(transport, "_preferred_kex", ()))
        kex_info = getattr(paramiko.Transport, "_kex_info", None)
        for legacy_kex in (
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1",
            "diffie-hellman-group1-sha1",
        ):
            if (not isinstance(kex_info, dict) or legacy_kex in kex_info) and legacy_kex not in cur_kex:
                cur_kex.append(legacy_kex)
        if cur_kex:
            transport._preferred_kex = tuple(cur_kex)
    except Exception:
        pass

    try:
        cur_keys = list(getattr(transport, "_preferred_keys", ()))
        for legacy_key in ("ssh-rsa", "ssh-dss"):
            if legacy_key not in cur_keys:
                cur_keys.append(legacy_key)
        if cur_keys:
            transport._preferred_keys = tuple(cur_keys)
    except Exception:
        pass

    try:
        orig_verify_key = getattr(transport, "_verify_key", None)
        if callable(orig_verify_key):
            def _compat_verify_key(host_key, sig):
                hk_type = getattr(transport, "host_key_type", None)
                if hk_type in ("ssh-rsa", "ssh-dss"):
                    key = _LegacySSHHostKey(data=host_key, expected_type=hk_type)
                    sig_msg = paramiko.Message(sig) if (paramiko is not None and hasattr(paramiko, "Message") and not hasattr(sig, "get_text")) else sig
                    if not key.verify_ssh_sig(transport.H, sig_msg):
                        raise paramiko.SSHException(f"Signature verification ({hk_type}) failed.")
                    transport.host_key = key
                    return
                return orig_verify_key(host_key, sig)
            transport._verify_key = _compat_verify_key
    except Exception:
        pass


def _default_transport_factory(sock):
    """
    Create a Paramiko SSH Transport bound to an already-connected TCP socket.
    Enables legacy KEX/host-key algorithms across Paramiko 2.x-5.x+ so older lab SSH
    targets (e.g., OpenSSH 4.7p1 on Metasploitable 2) complete handshake calibration cleanly.
    """
    t = paramiko.Transport(sock)
    _ensure_paramiko_legacy_algorithms(t)
    return t


def _classify_handshake_ssh_exception(exc):
    """Distinguish algorithm/cipher incompatibility from generic SSH handshake errors."""
    if isinstance(exc, getattr(paramiko, "IncompatiblePeer", ())):
        return "unsupported_algorithms"
    msg = str(exc).lower()
    algo_keywords = (
        "incompatible",
        "no acceptable",
        "algorithm",
        "cipher",
        "kex",
        "key exchange",
        "mac",
        "host key type",
        "agreed upon",
    )
    if any(kw in msg for kw in algo_keywords):
        return "unsupported_algorithms"
    return "handshake_error"


class SSHAdapter(ProtocolAdapter):
    """
    Protocol Adapter for Secure Shell (SSH-2.0, RFC 4252 / RFC 4253).

    Timing Separation:
    1. TCP Connection Establishment: Timed by scanner.py around socket.connect() only.
    2. SSH Protocol Setup:
       - In passive mode: post-TCP arrival of the 'SSH-2.0-...' version banner string.
       - In active SSH handshake/calibration mode: post-TCP execution of Transport.start_client()
         (version exchange, KEXINIT, Diffie-Hellman/ECDH key exchange, and NEWKEYS), strictly
         before any authentication request is transmitted.
    3. SSH Failed Authentication:
       - Timed per sequential Transport.auth_password(username, reject_token, fallback=False)
         exchange over the established SSH transport.
       - Separately tracks server-enforced session reuse limits (MaxAuthTries disconnect)
         versus uncensored lower bounds when probing stops before server disconnect.
    """

    protocol_id = "ssh"
    display_name = "SSH"
    default_ports = (22,)
    supports_passive_greeting = True
    supports_auth_calibration = True
    combines_setup_and_auth_session = True
    setup_stage_label = "SSH Handshake / Greeting"
    auth_stage_label = "rejected SSH userauth"

    def check_dependencies(self):
        if paramiko is None:
            raise ValueError("Active SSH calibration requires Paramiko; install requirements-ssh.txt")

    def matches_banner(self, banner):
        if not banner or not isinstance(banner, str):
            return False
        return banner.strip().upper().startswith("SSH-")

    def measure_setup(self, sock, target_ip, port, timeout_seconds=None, clock_fn=None, **kwargs):
        """
        Measure passive post-connect SSH banner arrival ('SSH-2.0-...') on an open socket.
        Does not initiate a cryptographic key exchange or send authentication packets.
        """
        if clock_fn is None:
            clock_fn = time.perf_counter
        start = clock_fn()
        try:
            raw = sock.recv(1024).decode("utf-8", errors="replace").strip()
            first_line = raw.split("\n")[0].strip() if raw else ""
            elapsed = clock_fn() - start
            if first_line:
                return first_line, {
                    "status": "received",
                    "display": first_line,
                    "raw_banner": first_line,
                    "status_code": None,
                    "protocol": self.protocol_id,
                    "setup_stage": "banner_greeting",
                    "protocol_overhead_seconds": elapsed,
                    "explanation": "Service banner read from TCP connection.",
                }, elapsed, "success"
            return "Not Detected", {
                "status": "empty_response",
                "display": "Not Detected",
                "raw_banner": None,
                "protocol": self.protocol_id,
                "setup_stage": "banner_greeting",
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
                "setup_stage": "banner_greeting",
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
                "setup_stage": "banner_greeting",
                "protocol_overhead_seconds": elapsed,
                "explanation": f"TCP connection succeeded, but banner read raised {type(exc).__name__}: {exc}",
            }, elapsed, "error"

    def _verify_host_key(self, transport, target_ip, port, known_hosts_path=None,
                         verify_host_key=True, allow_untrusted_host_key=False):
        """
        Evaluate remote server host key without globally disabling verification or silently ignoring trust.
        Any unverified-host laboratory mode requires explicit allow_untrusted_host_key=True opt-in.
        Returns (is_allowed_bool, host_key_status_str, host_key_error_or_None).
        """
        try:
            remote_key = transport.get_remote_server_key() if hasattr(transport, "get_remote_server_key") else None
        except Exception as exc:
            return False, "host_key_error", f"Failed to retrieve remote SSH host key: {exc}"

        key_type = remote_key.get_name() if (remote_key is not None and hasattr(remote_key, "get_name")) else "unknown"

        known_hosts_path = os.path.expanduser(known_hosts_path or "~/.ssh/known_hosts")
        if known_hosts_path is not None:
            if not os.path.isfile(known_hosts_path):
                if allow_untrusted_host_key:
                    return True, f"unverified_lab_opt_in ({key_type}; known_hosts not found)", None
                return (
                    False,
                    "host_key_unverified",
                    f"SSH known_hosts file '{known_hosts_path}' not found and allow_untrusted_host_key is False",
                )
            try:
                host_keys = paramiko.HostKeys(known_hosts_path)
                host_lookup = f"[{target_ip}]:{port}" if port != 22 else str(target_ip)
                matched = host_keys.check(host_lookup, remote_key) if remote_key is not None else False
                if matched:
                    return True, f"verified ({key_type})", None
                if allow_untrusted_host_key:
                    return True, f"unverified_lab_opt_in ({key_type}; host key mismatch overridden)", None
                return (
                    False,
                    "host_key_unverified",
                    f"Remote SSH host key ({key_type}) for {target_ip}:{port} did not match '{known_hosts_path}'",
                )
            except Exception as exc:
                if allow_untrusted_host_key:
                    return True, f"unverified_lab_opt_in ({key_type})", None
                return False, "host_key_unverified", f"SSH known_hosts verification error: {exc}"

        if allow_untrusted_host_key:
            return True, f"unverified_lab_opt_in ({key_type})", None

        return (
            False,
            "host_key_unverified",
            "SSH host key verification failed: no known_hosts file supplied and allow_untrusted_host_key is False (explicit opt-in required for unverified lab host keys)",
        )

    def measure_auth_session(
        self,
        sock,
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
        clock_fn=None,
        **kwargs,
    ):
        """
        Execute an explicitly authorized SSH handshake and failed-authentication calibration sequence
        on a freshly connected TCP socket (after socket.connect() has completed).
        Requires authorize_auth_probes=True explicitly; missing authorization never enables probes.
        Requires either a verified known_hosts entry or explicit allow_untrusted_host_key=True opt-in.

        Separately measures:
        - ssh_handshake_seconds: Transport.start_client() duration (version + KEX + NEWKEYS)
        - auth_total_seconds: Each Transport.auth_password(..., fallback=False) rejection duration
        - completed_attempts_in_connection: Empirical session reuse before server disconnect (MaxAuthTries)
        """
        if clock_fn is None:
            clock_fn = time.perf_counter
        clean_user = self.validate_auth_request(
            username=username,
            authorize_auth_probes=authorize_auth_probes,
            max_reuse_probes=max_reuse_probes,
            auth_timeout_seconds=auth_timeout_seconds,
        )
        self.check_dependencies()
        if reject_token is None:
            reject_token = config.SSH_PROBE_REJECT_TOKEN
        if max_reuse_probes is None:
            max_reuse_probes = config.SSH_MAX_REUSE_PROBES
        if auth_timeout_seconds is None:
            auth_timeout_seconds = config.SSH_AUTH_TIMEOUT
        if handshake_timeout_seconds is None:
            handshake_timeout_seconds = config.SSH_HANDSHAKE_TIMEOUT
        if (
            isinstance(handshake_timeout_seconds, bool)
            or not isinstance(handshake_timeout_seconds, (int, float))
            or handshake_timeout_seconds <= 0
        ):
            raise ValueError("handshake_timeout_seconds must be a positive number")

        if transport_factory is None:
            transport_factory = _default_transport_factory

        has_gettimeout = hasattr(sock, "gettimeout")
        prev_timeout = sock.gettimeout() if has_gettimeout else None
        if hasattr(sock, "settimeout"):
            sock.settimeout(handshake_timeout_seconds)

        transport = None
        handshake_sec = None
        handshake_outcome = None
        remote_banner = None
        host_key_status = None
        allowed_auth_types = None
        probe_records = []
        completed_in_session = 0
        closed_by_server = False
        termination_reason = "probe_cap_reached"
        disconnect_detection_sec = None

        try:
            t_hs_start = clock_fn()
            try:
                transport = transport_factory(sock)
                transport.banner_timeout = handshake_timeout_seconds
                transport.handshake_timeout = handshake_timeout_seconds
                transport.auth_timeout = auth_timeout_seconds
                transport.start_client(timeout=handshake_timeout_seconds)
                # Paramiko may return at the deadline before negotiation completes.
                if getattr(transport, "initial_kex_done", True) is False:
                    raise socket.timeout("SSH key exchange did not complete before the deadline")
                handshake_sec = clock_fn() - t_hs_start
                handshake_outcome = "success"
                remote_ver = getattr(transport, "remote_version", None)
                if remote_ver and isinstance(remote_ver, str) and remote_ver.strip():
                    remote_banner = remote_ver.strip()
            except socket.timeout:
                handshake_sec = clock_fn() - t_hs_start
                handshake_outcome = "timeout"
                termination_reason = "handshake_timeout"
                err_msg = f"SSH cryptographic handshake timed out after {handshake_timeout_seconds:g}s"
                return {
                    "protocol": self.protocol_id,
                    "handshake_seconds": handshake_sec,
                    "handshake_outcome": handshake_outcome,
                    "handshake_error": err_msg,
                    "session_error": err_msg,
                    "remote_banner": remote_banner,
                    "host_key_status": "not_reached",
                    "allowed_auth_types": None,
                    "completed_attempts_in_connection": 0,
                    "server_closed_connection": False,
                    "termination_reason": termination_reason,
                    "reuse_limit_is_lower_bound": False,
                    "disconnect_detection_seconds": None,
                    "max_reuse_probes_tested": max_reuse_probes,
                    "handshake_timeout_seconds": handshake_timeout_seconds,
                    "auth_timeout_seconds": auth_timeout_seconds,
                    "probes": [],
                }
            except paramiko.SSHException as exc:
                handshake_sec = clock_fn() - t_hs_start
                handshake_outcome = "error"
                termination_reason = _classify_handshake_ssh_exception(exc)
                err_msg = f"SSH handshake failed ({termination_reason}): {exc}"
                return {
                    "protocol": self.protocol_id,
                    "handshake_seconds": handshake_sec,
                    "handshake_outcome": handshake_outcome,
                    "handshake_error": err_msg,
                    "session_error": err_msg,
                    "remote_banner": remote_banner,
                    "host_key_status": "not_reached",
                    "allowed_auth_types": None,
                    "completed_attempts_in_connection": 0,
                    "server_closed_connection": False,
                    "termination_reason": termination_reason,
                    "reuse_limit_is_lower_bound": False,
                    "disconnect_detection_seconds": None,
                    "max_reuse_probes_tested": max_reuse_probes,
                    "handshake_timeout_seconds": handshake_timeout_seconds,
                    "auth_timeout_seconds": auth_timeout_seconds,
                    "probes": [],
                }
            except (EOFError, OSError) as exc:
                handshake_sec = clock_fn() - t_hs_start
                handshake_outcome = "error"
                is_conn_reset = isinstance(exc, (EOFError, ConnectionError)) or getattr(exc, "errno", None) in (
                    errno.ECONNRESET,
                    errno.EPIPE,
                    errno.ECONNABORTED,
                )
                termination_reason = "mid_exchange_disconnect" if is_conn_reset else "transport_error"
                err_msg = f"SSH transport error during handshake ({type(exc).__name__}): {exc}"
                return {
                    "protocol": self.protocol_id,
                    "handshake_seconds": handshake_sec,
                    "handshake_outcome": handshake_outcome,
                    "handshake_error": err_msg,
                    "session_error": err_msg,
                    "remote_banner": remote_banner,
                    "host_key_status": "not_reached",
                    "allowed_auth_types": None,
                    "completed_attempts_in_connection": 0,
                    "server_closed_connection": False,
                    "termination_reason": termination_reason,
                    "reuse_limit_is_lower_bound": False,
                    "disconnect_detection_seconds": None,
                    "max_reuse_probes_tested": max_reuse_probes,
                    "handshake_timeout_seconds": handshake_timeout_seconds,
                    "auth_timeout_seconds": auth_timeout_seconds,
                    "probes": [],
                }

            # Verify host key policy before transmitting any authentication credentials
            hk_ok, host_key_status, hk_err = self._verify_host_key(
                transport,
                target_ip=target_ip,
                port=port,
                known_hosts_path=known_hosts_path,
                verify_host_key=verify_host_key,
                allow_untrusted_host_key=allow_untrusted_host_key,
            )
            if not hk_ok:
                termination_reason = "host_key_unverified"
                return {
                    "protocol": self.protocol_id,
                    "handshake_seconds": handshake_sec,
                    "handshake_outcome": handshake_outcome,
                    "handshake_error": None,
                    "session_error": hk_err,
                    "remote_banner": remote_banner,
                    "host_key_status": host_key_status,
                    "allowed_auth_types": None,
                    "completed_attempts_in_connection": 0,
                    "server_closed_connection": False,
                    "termination_reason": termination_reason,
                    "reuse_limit_is_lower_bound": False,
                    "disconnect_detection_seconds": None,
                    "max_reuse_probes_tested": max_reuse_probes,
                    "handshake_timeout_seconds": handshake_timeout_seconds,
                    "auth_timeout_seconds": auth_timeout_seconds,
                    "probes": [],
                }

            # Apply dedicated authentication timeout for USERAUTH_REQUEST exchanges.
            # Do not overwrite sock.settimeout on a live paramiko.Transport (which relies on
            # _active_check_timeout=0.1s in its reader thread and uses transport.auth_timeout).
            if getattr(transport, "packetizer", None) is None and hasattr(sock, "settimeout"):
                sock.settimeout(auth_timeout_seconds)
            transport.auth_timeout = auth_timeout_seconds

            session_error = None
            for seq in range(1, max_reuse_probes + 1):
                if hasattr(transport, "is_active") and not transport.is_active():
                    if seq > 1 and completed_in_session > 0:
                        closed_by_server = True
                        termination_reason = "server_limit_after_auth"
                        disconnect_detection_sec = 0.0
                    else:
                        termination_reason = "mid_exchange_disconnect"
                        session_error = "SSH transport became inactive before authentication request"
                    break

                rec = {
                    "sequence_in_connection": seq,
                    "outcome": None,
                    "auth_total_seconds": None,
                    "server_closed_after": False,
                    "error": None,
                }
                t_auth_start = clock_fn()
                try:
                    transport.auth_password(clean_user, f"{reject_token}_{seq}", fallback=False)
                    t_auth_end = clock_fn()
                    rec["auth_total_seconds"] = t_auth_end - t_auth_start
                    rec["outcome"] = "successful"
                    rec["error"] = "Unexpected successful SSH authentication during calibration"
                    termination_reason = "unexpected_auth_success"
                    probe_records.append(rec)
                    break
                except paramiko.BadAuthenticationType as exc:
                    t_auth_end = clock_fn()
                    rec["auth_total_seconds"] = t_auth_end - t_auth_start
                    rec["outcome"] = "error"
                    allowed = list(getattr(exc, "allowed_types", []) or [])
                    allowed_auth_types = allowed
                    allowed_str = ", ".join(allowed) if allowed else "none"
                    rec["error"] = (
                        f"SSH password authentication not supported by server (allowed: {allowed_str})"
                    )
                    termination_reason = "password_auth_unsupported"
                    probe_records.append(rec)
                    break
                except paramiko.AuthenticationException as exc:
                    t_auth_end = clock_fn()
                    rec["auth_total_seconds"] = t_auth_end - t_auth_start
                    # Paramiko also raises AuthenticationException for timeouts and
                    # transport EOF; neither is a completed rejected authentication.
                    message = str(exc).lower()
                    if "timeout" in message or "timed out" in message:
                        rec["outcome"] = "timeout"
                        rec["error"] = str(exc)
                        termination_reason = "timeout"
                        probe_records.append(rec)
                        break
                    if "transport shut down" in message or "eof" in message:
                        if seq > 1 and completed_in_session > 0:
                            # OpenSSH closed the transport upon reaching MaxAuthTries after
                            # completed_in_session valid rejections.
                            closed_by_server = True
                            termination_reason = "server_limit_after_auth"
                            disconnect_detection_sec = t_auth_end - t_auth_start
                        else:
                            rec["outcome"] = "connection_closed"
                            rec["error"] = str(exc)
                            termination_reason = "mid_exchange_disconnect"
                            probe_records.append(rec)
                        break
                    rec["outcome"] = "rejected"
                    completed_in_session += 1
                    if hasattr(transport, "is_active") and not transport.is_active():
                        rec["server_closed_after"] = True
                        closed_by_server = True
                        termination_reason = "server_limit_after_auth"
                        disconnect_detection_sec = 0.0
                        probe_records.append(rec)
                        break
                    probe_records.append(rec)
                except socket.timeout:
                    rec["auth_total_seconds"] = clock_fn() - t_auth_start
                    rec["outcome"] = "timeout"
                    rec["error"] = (
                        f"Socket timeout ({auth_timeout_seconds:g}s) while awaiting SSH authentication response"
                    )
                    termination_reason = "timeout"
                    probe_records.append(rec)
                    break
                except paramiko.SSHException as exc:
                    elapsed_err = clock_fn() - t_auth_start
                    rec["auth_total_seconds"] = elapsed_err
                    msg_lower = str(exc).lower()
                    is_explicit_auth_limit = any(
                        k in msg_lower
                        for k in (
                            "too many authentication",
                            "maxauthtries",
                            "no existing session",
                            "session not active",
                            "socket is closed",
                        )
                    )
                    if seq > 1 and completed_in_session > 0 and is_explicit_auth_limit:
                        rec["outcome"] = "server_limit_disconnect"
                        rec["server_closed_after"] = True
                        rec["error"] = f"{type(exc).__name__}: {exc}"
                        closed_by_server = True
                        termination_reason = "server_limit_after_auth"
                        disconnect_detection_sec = elapsed_err
                        probe_records.append(rec)
                        break
                    is_disconnect = (
                        (hasattr(transport, "is_active") and not transport.is_active())
                        or any(k in msg_lower for k in ("disconnect", "closed", "reset", "eof"))
                    )
                    rec["outcome"] = "connection_closed" if is_disconnect else "error"
                    rec["server_closed_after"] = False
                    rec["error"] = f"{type(exc).__name__}: {exc}"
                    termination_reason = "mid_exchange_disconnect" if is_disconnect else "protocol_error"
                    probe_records.append(rec)
                    break
                except (EOFError, OSError) as exc:
                    elapsed_err = clock_fn() - t_auth_start
                    rec["auth_total_seconds"] = elapsed_err
                    is_conn_reset = isinstance(exc, (EOFError, ConnectionError)) or getattr(exc, "errno", None) in (
                        errno.ECONNRESET,
                        errno.EPIPE,
                        errno.ECONNABORTED,
                    )
                    rec["outcome"] = "connection_closed" if is_conn_reset else "error"
                    rec["server_closed_after"] = False
                    rec["error"] = f"{type(exc).__name__}: {exc}"
                    termination_reason = "mid_exchange_disconnect" if is_conn_reset else "transport_error"
                    probe_records.append(rec)
                    break
        finally:
            if transport is not None:
                try:
                    transport.close()
                except Exception:
                    pass
            if has_gettimeout and hasattr(sock, "settimeout"):
                try:
                    sock.settimeout(prev_timeout)
                except OSError:
                    pass

        # Normalize one-time first-probe userauth initialization delay (e.g., OpenSSH UseDNS
        # reverse-DNS timeout on seq=1) when subsequent probes in the same connection show
        # consistent steady-state PAM rejection timing.
        rej_probes = [
            p for p in probe_records
            if p.get("outcome") == "rejected" and p.get("auth_total_seconds") is not None
        ]
        if len(rej_probes) >= 3 and rej_probes[0].get("sequence_in_connection") == 1:
            t1 = rej_probes[0]["auth_total_seconds"]
            sub_times = [p["auth_total_seconds"] for p in rej_probes[1:]]
            sub_mean = sum(sub_times) / len(sub_times)
            if sub_mean > 0 and t1 > (sub_mean * 1.8) and (t1 - sub_mean) > 1.0:
                init_overhead = t1 - sub_mean
                amortized_init = init_overhead / len(rej_probes)
                rej_probes[0]["raw_first_probe_seconds"] = t1
                rej_probes[0]["userauth_init_overhead_seconds"] = init_overhead
                rej_probes[0]["auth_total_seconds"] = sub_mean
                for p in rej_probes:
                    p["auth_total_seconds"] += amortized_init

        return {
            "protocol": self.protocol_id,
            "handshake_seconds": handshake_sec,
            "handshake_outcome": handshake_outcome,
            "handshake_error": None,
            "session_error": session_error,
            "remote_banner": remote_banner,
            "host_key_status": host_key_status,
            "allowed_auth_types": allowed_auth_types,
            "completed_attempts_in_connection": completed_in_session,
            "server_closed_connection": closed_by_server,
            "termination_reason": termination_reason,
            "reuse_limit_is_lower_bound": (termination_reason == "probe_cap_reached" and completed_in_session > 0),
            "disconnect_detection_seconds": disconnect_detection_sec,
            "max_reuse_probes_tested": max_reuse_probes,
            "handshake_timeout_seconds": handshake_timeout_seconds,
            "auth_timeout_seconds": auth_timeout_seconds,
            "probes": probe_records,
        }
