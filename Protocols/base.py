# protocols/base.py
# Protocol Adapter interface and registry for NAFAT multi-protocol timing and feasibility assessment.

import socket
import time

import config


class ProtocolAdapter:
    """
    Base interface for protocol-specific setup and authentication timing adapters in NAFAT.

    Responsibilities of a ProtocolAdapter:
    1. Service & capability identification (default ports, banner matching, capability flags).
    2. Post-TCP protocol setup / handshake timing (strictly after socket.connect() completes).
    3. Explicit authorization validation inside the adapter before any active authentication probe.
    4. Controlled failed-authentication timing and server session-reuse (K_srv) observation.

    Shared responsibilities that remain OUTSIDE protocol adapters:
    - Fresh IPv4 TCP connection establishment timing (scanner.py)
    - Sample dispersion, CV classification, and statistical aggregation (scanner.py)
    - Workload feasibility math, reuse resolution (K_eff), and confidence classification (calculator.py)
    - Terminal TXT and JSON report rendering and persistence (report.py)
    """

    protocol_id = "generic"
    display_name = "Generic TCP"
    default_ports = ()
    supports_passive_greeting = True
    supports_auth_calibration = False
    combines_setup_and_auth_session = False
    setup_stage_label = "Post-TCP Greeting"
    auth_stage_label = "authentication"

    def matches_banner(self, banner):
        """Return True if the observed banner string uniquely identifies this protocol."""
        return False

    def identify_service(self, port, banner=None):
        """Return structured service capability metadata for the given port and optional banner."""
        return {
            "protocol_id": self.protocol_id,
            "display_name": self.display_name,
            "port": port,
            "supports_passive_greeting": self.supports_passive_greeting,
            "supports_auth_calibration": self.supports_auth_calibration,
            "combines_setup_and_auth_session": self.combines_setup_and_auth_session,
            "setup_stage_label": self.setup_stage_label,
            "auth_stage_label": self.auth_stage_label,
            "banner_matched": self.matches_banner(banner) if banner else False,
        }

    def validate_auth_request(self, username, authorize_auth_probes, max_reuse_probes=None, auth_timeout_seconds=None):
        """
        Enforce explicit authorization and parameter safety inside the adapter/engine itself.
        If username is None, automatically assumes config.DEFAULT_CALIBRATION_USER.
        Raises ValueError if authentication probing is unsupported, unauthorized, or given a blank string.
        """
        if not self.supports_auth_calibration:
            raise ValueError(
                f"Protocol adapter '{self.display_name}' ({self.protocol_id}) does not support active authentication calibration"
            )
        if username is None:
            username = config.DEFAULT_CALIBRATION_USER
        if not isinstance(username, str) or not username.strip():
            raise ValueError(f"An explicit authorized {self.display_name} test username is required")
        if not authorize_auth_probes:
            raise ValueError(
                f"Active {self.display_name} authentication probes require authorize_auth_probes=True"
            )
        if max_reuse_probes is not None:
            if isinstance(max_reuse_probes, bool) or not isinstance(max_reuse_probes, int) or max_reuse_probes < 1:
                raise ValueError("max_reuse_probes must be a positive integer")
        if auth_timeout_seconds is not None:
            if (
                isinstance(auth_timeout_seconds, bool)
                or not isinstance(auth_timeout_seconds, (int, float))
                or auth_timeout_seconds <= 0
            ):
                raise ValueError("auth_timeout_seconds must be a positive number")
        return username.strip()

    def measure_setup(self, sock, target_ip, port, timeout_seconds=None, clock_fn=None, **kwargs):
        """
        Measure dynamic post-connect protocol greeting or handshake overhead.
        Must be called AFTER socket.connect() has completed so TCP latency is never double-counted.
        Returns (concise_display_banner, banner_info_dict, protocol_elapsed_seconds, protocol_outcome).
        """
        if clock_fn is None:
            clock_fn = time.perf_counter
        if port == 443:
            return "Not Detected", {
                "status": "skipped_tls",
                "display": "Not Detected",
                "raw_banner": None,
                "protocol": "tls",
                "explanation": "Port 443 typically expects a TLS handshake; plaintext probing is skipped.",
            }, None, "skipped_tls"

        start = clock_fn()
        try:
            if port == 80:
                request = f"HEAD / HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n"
                sock.sendall(request.encode("ascii"))
            raw = sock.recv(1024).decode("utf-8", errors="replace").strip()
            first_line = raw.split("\n")[0].strip() if raw else ""
            code = first_line[:3] if len(first_line) >= 3 and first_line[:3].isdigit() else None
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

    def measure_auth_session(self, sock, username, reject_token=None, max_reuse_probes=None,
                             auth_timeout_seconds=None, **kwargs):
        """
        Execute an explicitly authorized failed-authentication calibration sequence on an open connection.
        Subclasses supporting authentication calibration must override this method.
        """
        raise NotImplementedError(
            f"Protocol adapter '{self.display_name}' ({self.protocol_id}) does not implement measure_auth_session"
        )


class ProtocolRegistry:
    """
    Registry mapping protocol identifiers, default TCP ports, and service banners to ProtocolAdapter instances.
    """

    def __init__(self):
        self._by_id = {}
        self._by_port = {}
        self._fallback = ProtocolAdapter()

    def register(self, adapter):
        """Register a ProtocolAdapter instance by protocol_id and its default_ports."""
        if not isinstance(adapter, ProtocolAdapter):
            raise TypeError("adapter must be an instance of ProtocolAdapter")
        proto_id = adapter.protocol_id.strip().lower()
        if not proto_id:
            raise ValueError("adapter.protocol_id must be a non-empty string")
        self._by_id[proto_id] = adapter
        for port in adapter.default_ports:
            self._by_port[int(port)] = adapter
        return adapter

    def get_by_name(self, protocol_name):
        """Look up a registered adapter by protocol name (case-insensitive), or None if not registered."""
        if not protocol_name or not isinstance(protocol_name, str):
            return None
        return self._by_id.get(protocol_name.strip().lower())

    def get_by_port(self, port):
        """Look up a registered adapter by default port number, or None if not mapped."""
        if isinstance(port, bool) or not isinstance(port, int):
            return None
        return self._by_port.get(port)

    def detect_from_banner(self, banner):
        """Inspect a banner string to see if any registered adapter recognizes the service protocol."""
        if not banner or not isinstance(banner, str) or banner == "Not Detected":
            return None
        for adapter in self._by_id.values():
            if adapter.matches_banner(banner):
                return adapter
        return None

    def resolve(self, port, protocol_name=None, banner=None):
        """
        Resolve the most specific ProtocolAdapter for an endpoint:
        1. Explicit protocol_name (if provided: returns matching registered adapter, or generic fallback if unregistered; never falls back to another protocol adapter)
        2. Default port mapping (e.g., 21 -> FTP, 22 -> SSH)
        3. Banner-based detection (for nonstandard ports where a recognizable banner was read)
        4. Generic fallback adapter (passive banner read only; no auth calibration)
        """
        if protocol_name:
            explicit = self.get_by_name(protocol_name)
            if explicit is not None:
                return explicit
            return self._fallback
        by_port = self.get_by_port(port)
        if by_port is not None:
            return by_port
        by_banner = self.detect_from_banner(banner)
        if by_banner is not None:
            return by_banner
        return self._fallback

    def list_protocols(self):
        """Return a sorted list of registered protocol IDs."""
        return sorted(self._by_id.keys())
