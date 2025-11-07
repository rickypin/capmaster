#!/usr/bin/env python3
"""
Verification script for flow hash implementation.

This script verifies that the flow hash implementation matches the reference
Python code provided by the user.
"""

import sys
sys.path.insert(0, '/Users/ricky/Downloads/code/capmaster')

from capmaster.plugins.compare.flow_hash import calculate_flow_hash


def main():
    """Run verification tests."""
    print("=" * 70)
    print("Flow Hash Implementation Verification")
    print("=" * 70)
    print()
    
    # Test case from the reference implementation
    test_cases = [
        {
            "name": "Reference case",
            "ip1": "8.67.2.125",
            "ip2": "8.42.96.45",
            "port1": 26302,
            "port2": 35101,
            "expected": -1173584886679544929,
        },
    ]
    
    all_passed = True
    
    for i, test in enumerate(test_cases, 1):
        print(f"Test {i}: {test['name']}")
        print(f"  Input: {test['ip1']}:{test['port1']} -> {test['ip2']}:{test['port2']}")
        
        hash_val, flow_side = calculate_flow_hash(
            test['ip1'], test['ip2'], test['port1'], test['port2'], 6
        )
        
        print(f"  Expected: {test['expected']}")
        print(f"  Actual:   {hash_val}")
        print(f"  Flow side: {flow_side}")
        
        if hash_val == test['expected']:
            print(f"  Result: ✓ PASS")
        else:
            print(f"  Result: ✗ FAIL")
            all_passed = False
        
        print()
    
    print("=" * 70)
    if all_passed:
        print("✓ All tests PASSED")
        print("=" * 70)
        return 0
    else:
        print("✗ Some tests FAILED")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())

