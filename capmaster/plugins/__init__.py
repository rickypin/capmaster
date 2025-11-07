"""Plugin registration and discovery."""

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
    """
    # Import plugins to trigger registration
    # This will be populated as we implement each plugin
    try:
        import capmaster.plugins.analyze  # noqa: F401
    except ImportError:
        pass

    try:
        import capmaster.plugins.match  # noqa: F401
    except ImportError:
        pass

    try:
        import capmaster.plugins.filter  # noqa: F401
    except ImportError:
        pass

    try:
        import capmaster.plugins.clean  # noqa: F401
    except ImportError:
        pass

    try:
        import capmaster.plugins.compare  # noqa: F401
    except ImportError:
        pass


__all__ = ["PluginBase", "register_plugin", "get_all_plugins", "discover_plugins"]
