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
    Only catches ModuleNotFoundError for missing modules, allowing other
    import errors to propagate.
    """
    import importlib.util

    # List of all analysis module names
    module_names = [
        "protocol_hierarchy",
        "ipv4_conversations",
        "ipv4_source_ttls",
        "ipv4_destinations",
        "ipv4_hosts",
        "tcp_conversations",
        "tcp_zero_window",
        "tcp_duration",
        "tcp_completeness",
        "udp_conversations",
        "dns_stats",
        "dns_qr_stats",
        "tls_alert",
        "http_stats",
        "http_response",
        "ftp_stats",
        "icmp_stats",
        "sip_stats",
        "rtp_stats",
        "ssh_stats",
        "json_stats",
        "xml_stats",
        "ftp_data_stats",
        "mq_stats",
        "voip_quality",
        "mgcp_stats",
        "rtcp_stats",
        "sdp_stats",
    ]

    for module_name in module_names:
        full_module_name = f"capmaster.plugins.analyze.modules.{module_name}"
        # Check if module exists before importing
        spec = importlib.util.find_spec(full_module_name)
        if spec is not None:
            # Module exists, import it (let any import errors propagate)
            __import__(full_module_name)
        # If module doesn't exist, silently skip it


__all__ = [
    "AnalysisModule",
    "register_module",
    "get_all_modules",
    "discover_modules",
]
