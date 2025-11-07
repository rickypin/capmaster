#!/usr/bin/env python3
"""Test script to verify microsecond rounding functionality."""


def round_to_microseconds(timestamp_seconds: float) -> int:
    """
    Convert timestamp from seconds to nanoseconds and round to microsecond precision.
    
    Args:
        timestamp_seconds: Unix timestamp in seconds (float)
    
    Returns:
        Timestamp in nanoseconds (int), rounded to microsecond precision
        
    Example:
        Input:  1.757441703689601024 seconds
        Output: 1757441703689601000 nanoseconds (rounded to nearest microsecond)
    """
    # Convert to microseconds first, round, then convert to nanoseconds
    timestamp_microseconds = round(timestamp_seconds * 1_000_000)
    timestamp_nanoseconds = timestamp_microseconds * 1_000
    return timestamp_nanoseconds


def test_rounding():
    """Test the rounding function with example values."""
    
    print("=" * 80)
    print("Testing Microsecond Rounding Function")
    print("=" * 80)
    
    # Test case 1: From the user's example
    test_cases = [
        {
            "name": "Example 1 (from user)",
            "input_ns": 1757441703689601024,
            "expected_ns": 1757441703689601000,
        },
        {
            "name": "Example 2 (from user)",
            "input_ns": 1757445296366606848,
            "expected_ns": 1757445296366607000,
        },
        {
            "name": "Test case 3 (round down)",
            "input_ns": 1459996923372072400,
            "expected_ns": 1459996923372072000,
        },
        {
            "name": "Test case 4 (round up)",
            "input_ns": 1459996923372072600,
            "expected_ns": 1459996923372073000,
        },
        {
            "name": "Test case 5 (exact microsecond)",
            "input_ns": 1459996923372072000,
            "expected_ns": 1459996923372072000,
        },
    ]
    
    all_passed = True
    
    for test in test_cases:
        print(f"\n{test['name']}:")
        print(f"  Input (ns):    {test['input_ns']}")
        
        # Convert input nanoseconds to seconds
        input_seconds = test['input_ns'] / 1_000_000_000
        
        # Apply rounding function
        result_ns = round_to_microseconds(input_seconds)
        
        print(f"  Expected (ns): {test['expected_ns']}")
        print(f"  Result (ns):   {result_ns}")
        
        # Check if result matches expected
        if result_ns == test['expected_ns']:
            print(f"  ✓ PASSED")
        else:
            print(f"  ✗ FAILED")
            all_passed = False
            
        # Show the difference in nanoseconds
        diff = abs(test['input_ns'] - result_ns)
        print(f"  Difference:    {diff} ns")
        
        # Show last 3 digits (should be 000 after rounding)
        last_3_digits = result_ns % 1000
        print(f"  Last 3 digits: {last_3_digits:03d} (should be 000)")
    
    print("\n" + "=" * 80)
    if all_passed:
        print("✓ All tests PASSED!")
    else:
        print("✗ Some tests FAILED!")
    print("=" * 80)
    
    return all_passed


def demonstrate_precision():
    """Demonstrate the precision change."""
    
    print("\n" + "=" * 80)
    print("Precision Demonstration")
    print("=" * 80)
    
    # Original timestamp with nanosecond precision
    original_ns = 1757441703689601024
    original_seconds = original_ns / 1_000_000_000
    
    print(f"\nOriginal timestamp:")
    print(f"  Nanoseconds:  {original_ns}")
    print(f"  Seconds:      {original_seconds:.9f}")
    
    # After rounding to microseconds
    rounded_ns = round_to_microseconds(original_seconds)
    rounded_seconds = rounded_ns / 1_000_000_000
    
    print(f"\nAfter rounding to microseconds:")
    print(f"  Nanoseconds:  {rounded_ns}")
    print(f"  Seconds:      {rounded_seconds:.9f}")
    
    print(f"\nPrecision change:")
    print(f"  Original last 3 digits:  {original_ns % 1000:03d}")
    print(f"  Rounded last 3 digits:   {rounded_ns % 1000:03d}")
    print(f"  Difference:              {abs(original_ns - rounded_ns)} ns")
    
    # Show that the output format remains the same (19 digits)
    print(f"\nOutput format:")
    print(f"  Original length: {len(str(original_ns))} digits")
    print(f"  Rounded length:  {len(str(rounded_ns))} digits")
    print(f"  ✓ Format unchanged (both 19 digits)")


if __name__ == "__main__":
    # Run tests
    test_passed = test_rounding()
    
    # Demonstrate precision
    demonstrate_precision()
    
    # Exit with appropriate code
    exit(0 if test_passed else 1)

