"""Analysis modules registration and discovery."""

from capmaster.plugins.analyze.modules.base import AnalysisModule

# Registry of all available analysis modules
_MODULE_REGISTRY: list[type[AnalysisModule]] = []


def register_module(module_class: type[AnalysisModule]) -> type[AnalysisModule]:
    """
    Decorator to register an analysis module class.

    Args:
        module_class: Analysis module class to register

    Returns:
        The same module class (for use as decorator)
    """
    _MODULE_REGISTRY.append(module_class)
    return module_class


def get_all_modules() -> list[type[AnalysisModule]]:
    """
    Get all registered analysis modules.

    Returns:
        List of analysis module classes
    """
    return _MODULE_REGISTRY.copy()


def discover_modules() -> None:
    """
    Discover and import all analysis modules.

    This function imports all module files to trigger their registration.
    """
    # Import all modules to trigger registration
    try:
        from capmaster.plugins.analyze.modules import protocol_hierarchy  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import ipv4_conversations  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import ipv4_source_ttls  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import ipv4_destinations  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import ipv4_hosts  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import tcp_conversations  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import tcp_zero_window  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import tcp_duration  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import tcp_completeness  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import udp_conversations  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import dns_stats  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import dns_qr_stats  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import tls_alert  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import http_stats  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import http_response  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import ftp_stats  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import icmp_stats  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import sip_stats  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import rtp_stats  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import ssh_stats  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import json_stats  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import xml_stats  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import ftp_data_stats  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import mq_stats  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import voip_quality  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import mgcp_stats  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import rtcp_stats  # noqa: F401
    except ImportError:
        pass

    try:
        from capmaster.plugins.analyze.modules import sdp_stats  # noqa: F401
    except ImportError:
        pass


__all__ = [
    "AnalysisModule",
    "register_module",
    "get_all_modules",
    "discover_modules",
]
