# protocols/__init__.py
# Protocol Adapter registry and built-in adapters (FTP, SSH) for NAFAT.

from protocols.base import ProtocolAdapter, ProtocolRegistry
from protocols.ftp_adapter import FTPAdapter, read_ftp_response
from protocols.ssh_adapter import SSHAdapter

DEFAULT_REGISTRY = ProtocolRegistry()
FTP_ADAPTER = DEFAULT_REGISTRY.register(FTPAdapter())
SSH_ADAPTER = DEFAULT_REGISTRY.register(SSHAdapter())


def get_adapter_for_endpoint(port, protocol_name=None, banner=None, registry=None):
    """Resolve the appropriate ProtocolAdapter for a given port, optional protocol override, or banner."""
    reg = registry if registry is not None else DEFAULT_REGISTRY
    return reg.resolve(port=port, protocol_name=protocol_name, banner=banner)


def register_adapter(adapter, registry=None):
    """Register a custom ProtocolAdapter into the active protocol registry."""
    reg = registry if registry is not None else DEFAULT_REGISTRY
    return reg.register(adapter)


__all__ = [
    "ProtocolAdapter",
    "ProtocolRegistry",
    "FTPAdapter",
    "SSHAdapter",
    "FTP_ADAPTER",
    "SSH_ADAPTER",
    "DEFAULT_REGISTRY",
    "get_adapter_for_endpoint",
    "register_adapter",
    "read_ftp_response",
]
