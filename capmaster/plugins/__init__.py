"""Plugin registration and discovery."""

from __future__ import annotations

from capmaster.plugins.base import PluginBase

# Registry of all available plugins
_PLUGIN_REGISTRY: list[type[PluginBase]] = []


def register_plugin(plugin_class: type[PluginBase]) -> type[PluginBase]:
    """
    Decorator to register a plugin class.

    Args:
        plugin_class: Plugin class to register

    Returns:
        The same plugin class (for use as decorator)
    """
    _PLUGIN_REGISTRY.append(plugin_class)
    return plugin_class


def get_all_plugins() -> list[type[PluginBase]]:
    """
    Get all registered plugins.

    Returns:
        List of plugin classes
    """
    return _PLUGIN_REGISTRY.copy()


def discover_plugins() -> None:
    """
    Discover and import all plugins.

    This function imports all plugin modules to trigger their registration.
    Only catches ModuleNotFoundError for missing plugins, allowing other
    import errors to propagate.
    """
    import importlib.util

    # List of plugin module names to discover
    plugin_modules = [
        "capmaster.plugins.analyze",
        "capmaster.plugins.match",
        "capmaster.plugins.compare",
        "capmaster.plugins.preprocess",
        "capmaster.plugins.topology",
        "capmaster.plugins.streamdiff",
    ]

    for module_name in plugin_modules:
        # Check if module exists before importing
        spec = importlib.util.find_spec(module_name)
        if spec is not None:
            # Module exists, import it (let any import errors propagate)
            __import__(module_name)
        # If module doesn't exist, silently skip it


__all__ = ["PluginBase", "register_plugin", "get_all_plugins", "discover_plugins"]
