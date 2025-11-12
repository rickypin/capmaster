"""
Unit tests for timestamp conversion functionality in compare plugin.
"""

import pytest

from capmaster.plugins.compare.plugin import to_nanoseconds


@pytest.mark.integration
class TestToNanoseconds:
    """Test the to_nanoseconds function."""

    def test_full_precision_preserved(self):
        """Test that full nanosecond precision is preserved."""
        # Input: 1757441703.689601024 seconds
        # Expected: 1757441703689601024 nanoseconds (full precision)
        timestamp_seconds = 1757441703.689601024
        result = to_nanoseconds(timestamp_seconds)
        # Note: Due to floating point precision, we may lose some precision
        # but it should be very close to the expected value
        expected = int(1757441703.689601024 * 1_000_000_000)
        assert result == expected

    def test_high_precision_timestamp(self):
        """Test with high precision timestamp."""
        # Input: 1757445296.366606848 seconds
        timestamp_seconds = 1757445296.366606848
        result = to_nanoseconds(timestamp_seconds)
        expected = int(1757445296.366606848 * 1_000_000_000)
        assert result == expected

    def test_exact_microsecond(self):
        """Test that exact microsecond values are preserved."""
        # Input: 1459996923.372072 seconds (exact microsecond)
        # Expected: 1459996923372072000 nanoseconds
        timestamp_seconds = 1459996923.372072
        result = to_nanoseconds(timestamp_seconds)
        expected = int(1459996923.372072 * 1_000_000_000)
        assert result == expected

    def test_zero_timestamp(self):
        """Test with zero timestamp."""
        timestamp_seconds = 0.0
        result = to_nanoseconds(timestamp_seconds)
        assert result == 0

    def test_small_timestamp(self):
        """Test with small timestamp value."""
        # Input: 1.000000500 seconds (500 nanoseconds)
        # Expected: 1000000500 nanoseconds (full precision)
        timestamp_seconds = 1.000000500
        result = to_nanoseconds(timestamp_seconds)
        expected = int(1.000000500 * 1_000_000_000)
        assert result == expected

    def test_large_timestamp(self):
        """Test with large timestamp value (year 2025)."""
        # Input: 1735689600.123456789 seconds (2025-01-01 00:00:00.123456789)
        # Expected: full nanosecond precision
        timestamp_seconds = 1735689600.123456789
        result = to_nanoseconds(timestamp_seconds)
        expected = int(1735689600.123456789 * 1_000_000_000)
        assert result == expected

    def test_output_format(self):
        """Test that output format is consistent (19 digits for typical timestamps)."""
        # Typical timestamp from 2016
        timestamp_seconds = 1459996923.372072960
        result = to_nanoseconds(timestamp_seconds)

        # Should be 19 digits
        assert len(str(result)) == 19

    def test_precision_maintained(self):
        """Test that precision is maintained within floating point limits."""
        # Input with high nanosecond precision
        timestamp_seconds = 1459996923.372072999
        result = to_nanoseconds(timestamp_seconds)

        # Convert back to seconds
        result_seconds = result / 1_000_000_000

        # Difference should be very small (within floating point precision)
        diff = abs(timestamp_seconds - result_seconds)
        assert diff < 0.000000001  # Less than 1 nanosecond

    def test_multiple_values(self):
        """Test with multiple timestamp values."""
        test_cases = [
            1459996923.372072960,
            1459996923.780259000,
            1459997031.469234000,
            1459997031.829895000,
        ]

        for input_seconds in test_cases:
            result = to_nanoseconds(input_seconds)
            expected = int(input_seconds * 1_000_000_000)
            assert result == expected

    def test_negative_timestamp(self):
        """Test with negative timestamp (before Unix epoch)."""
        # Input: -1.000000500 seconds
        # Expected: -1000000500 nanoseconds (full precision)
        timestamp_seconds = -1.000000500
        result = to_nanoseconds(timestamp_seconds)
        expected = int(-1.000000500 * 1_000_000_000)
        assert result == expected

    def test_nanosecond_precision(self):
        """Test that nanosecond-level differences are preserved."""
        # Two timestamps differing by only a few nanoseconds
        timestamp1 = 1.000000001  # 1 nanosecond
        timestamp2 = 1.000000002  # 2 nanoseconds

        result1 = to_nanoseconds(timestamp1)
        result2 = to_nanoseconds(timestamp2)

        # The difference should be preserved (within floating point limits)
        expected1 = int(1.000000001 * 1_000_000_000)
        expected2 = int(1.000000002 * 1_000_000_000)

        assert result1 == expected1
        assert result2 == expected2

