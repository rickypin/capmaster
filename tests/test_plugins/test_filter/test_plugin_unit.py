"""Unit tests for filter plugin using mocks.

These tests use mocking to avoid dependency on tshark and real PCAP files.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from capmaster.plugins.filter.detector import OneWayDetector
from capmaster.plugins.filter.plugin import FilterPlugin


class TestOneWayDetectorUnit:
    """Unit tests for OneWayDetector with mocking."""

    def test_detector_initialization(self):
        """Test detector can be initialized."""
        detector = OneWayDetector()
        assert detector is not None

    def test_detector_has_analyze_method(self):
        """Test detector has analyze method."""
        detector = OneWayDetector()
        assert hasattr(detector, 'analyze')
        assert callable(detector.analyze)




class TestFilterPluginUnit:
    """Unit tests for FilterPlugin."""

    def test_plugin_name(self):
        """Test plugin name."""
        plugin = FilterPlugin()
        assert plugin.name == "filter"

    def test_plugin_has_required_methods(self):
        """Test that plugin has all required methods."""
        plugin = FilterPlugin()

        assert hasattr(plugin, 'name')
        assert hasattr(plugin, 'execute')
        assert hasattr(plugin, 'setup_cli')
        assert callable(plugin.execute)
        assert callable(plugin.setup_cli)

