"""Analyze plugin package."""

from capmaster.plugins import register_plugin
from capmaster.plugins.analyze.plugin import AnalyzePlugin

# Register the analyze plugin
register_plugin(AnalyzePlugin)

__all__ = ["AnalyzePlugin"]
