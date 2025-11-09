"""
Unit tests for timestamp rounding functionality in compare plugin.
"""

import pytest

from capmaster.plugins.compare.plugin import round_to_microseconds


@pytest.mark.integration
class TestRoundToMicroseconds:
    """Test the round_to_microseconds function."""

    def test_round_down(self):
        """Test rounding down when nanoseconds < 500."""
        # Input: 1757441703.689601024 seconds
        # Expected: 1757441703689601000 nanoseconds (rounded down)
        timestamp_seconds = 1757441703.689601024
        result = round_to_microseconds(timestamp_seconds)
        assert result == 1757441703689601000
        assert result % 1000 == 0  # Last 3 digits should be 000

    def test_round_up(self):
        """Test rounding up when nanoseconds >= 500."""
        # Input: 1757445296.366606848 seconds
        # Expected: 1757445296366607000 nanoseconds (rounded up)
        timestamp_seconds = 1757445296.366606848
        result = round_to_microseconds(timestamp_seconds)
        assert result == 1757445296366607000
        assert result % 1000 == 0  # Last 3 digits should be 000

    def test_exact_microsecond(self):
        """Test that exact microsecond values remain unchanged."""
        # Input: 1459996923.372072 seconds (exact microsecond)
        # Expected: 1459996923372072000 nanoseconds (no change)
        timestamp_seconds = 1459996923.372072
        result = round_to_microseconds(timestamp_seconds)
        assert result == 1459996923372072000
        assert result % 1000 == 0  # Last 3 digits should be 000

    def test_zero_timestamp(self):
        """Test with zero timestamp."""
        timestamp_seconds = 0.0
        result = round_to_microseconds(timestamp_seconds)
        assert result == 0
        assert result % 1000 == 0

    def test_small_timestamp(self):
        """Test with small timestamp value."""
        # Input: 1.000000500 seconds (500 nanoseconds)
        # Expected: 1000001000 nanoseconds (rounded up to 1 microsecond)
        timestamp_seconds = 1.000000500
        result = round_to_microseconds(timestamp_seconds)
        assert result == 1000001000
        assert result % 1000 == 0

    def test_large_timestamp(self):
        """Test with large timestamp value (year 2025)."""
        # Input: 1735689600.123456789 seconds (2025-01-01 00:00:00.123456789)
        # Expected: 1735689600123457000 nanoseconds (rounded to microsecond)
        timestamp_seconds = 1735689600.123456789
        result = round_to_microseconds(timestamp_seconds)
        assert result == 1735689600123457000
        assert result % 1000 == 0

    def test_output_format(self):
        """Test that output format is consistent (19 digits for typical timestamps)."""
        # Typical timestamp from 2016
        timestamp_seconds = 1459996923.372072960
        result = round_to_microseconds(timestamp_seconds)
        
        # Should be 19 digits
        assert len(str(result)) == 19
        
        # Last 3 digits should be 000
        assert result % 1000 == 0

    def test_precision_loss(self):
        """Test that precision loss is within acceptable range (< 1 microsecond)."""
        # Input with high nanosecond precision
        timestamp_seconds = 1459996923.372072999
        result = round_to_microseconds(timestamp_seconds)
        
        # Convert back to seconds
        result_seconds = result / 1_000_000_000
        
        # Difference should be less than 1 microsecond (0.000001 seconds)
        diff = abs(timestamp_seconds - result_seconds)
        assert diff < 0.000001

    def test_multiple_values(self):
        """Test with multiple timestamp values."""
        test_cases = [
            (1459996923.372072960, 1459996923372073000),
            (1459996923.780259000, 1459996923780259000),
            (1459997031.469234000, 1459997031469234000),
            (1459997031.829895000, 1459997031829895000),
        ]
        
        for input_seconds, expected_ns in test_cases:
            result = round_to_microseconds(input_seconds)
            assert result == expected_ns
            assert result % 1000 == 0

    def test_negative_timestamp(self):
        """Test with negative timestamp (before Unix epoch)."""
        # Input: -1.000000500 seconds
        # Expected: -1000001000 nanoseconds (rounded)
        timestamp_seconds = -1.000000500
        result = round_to_microseconds(timestamp_seconds)
        assert result == -1000001000
        assert result % 1000 == 0

    def test_fractional_microsecond_boundary(self):
        """Test rounding at the 0.5 nanosecond boundary."""
        # Test case 1: exactly 0.5 nanoseconds (should round to nearest even)
        timestamp_seconds = 1.0000005005  # 1000000500.5 nanoseconds
        result = round_to_microseconds(timestamp_seconds)
        # Python's round() uses banker's rounding (round to nearest even)
        # 1000000.5005 microseconds rounds to 1000001 microseconds
        assert result == 1000001000
        assert result % 1000 == 0

