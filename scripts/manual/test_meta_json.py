#!/usr/bin/env python3
"""Manual/local test script to verify meta.json file generation for match commands.

NOTE:
- This script expects test data under data/2hops/dbs_1112_2/ inside the repo root.
- It is not collected by pytest; treat it as a personal helper/legacy script.
"""

import json
import subprocess
import sys
from pathlib import Path


def test_meta_json_exists(output_file: Path) -> bool:
    """Check if meta.json file exists alongside the output file."""
    meta_file = output_file.parent / f"{output_file.stem}.meta.json"
    return meta_file.exists()


def test_meta_json_content(output_file: Path) -> dict:
    """Read and validate meta.json content."""
    meta_file = output_file.parent / f"{output_file.stem}.meta.json"
    
    if not meta_file.exists():
        raise FileNotFoundError(f"Meta file not found: {meta_file}")
    
    with open(meta_file, 'r', encoding='utf-8') as f:
        content = json.load(f)
    
    # Validate required fields
    if "id" not in content:
        raise ValueError("Missing 'id' field in meta.json")
    if "source" not in content:
        raise ValueError("Missing 'source' field in meta.json")
    
    return content


def main():
    """Main test function."""
    print("Testing meta.json generation for match commands...")
    print("=" * 80)
    
    # Test data directory
    test_dir = Path("data/2hops/dbs_1112_2/")
    
    if not test_dir.exists():
        print(f"Error: Test directory not found: {test_dir}")
        print("Please update the test_dir path in the script.")
        return 1
    
    # Create artifacts/tmp directory for outputs
    tmp_dir = Path("artifacts/tmp")
    tmp_dir.mkdir(exist_ok=True)
    
    tests = [
        {
            "name": "Match command",
            "cmd": ["python", "-m", "capmaster", "match", "-i", str(test_dir), "-o", str(tmp_dir / "test_matched_connections.txt")],
            "output": tmp_dir / "test_matched_connections.txt",
            "expected_id": "matched_connections",
            "expected_source": "basic",
        },
        {
            "name": "Match topology command",
            "cmd": [
                "python",
                "-m",
                "capmaster",
                "topology",
                "-i",
                str(test_dir),
                "--matched-connections",
                str(tmp_dir / "test_matched_connections.txt"),
                "-o",
                str(tmp_dir / "test_topology.txt"),
            ],
            "output": tmp_dir / "test_topology.txt",
            "expected_id": "topology",
            "expected_source": "basic",
        },
    ]
    
    results = []
    
    for test in tests:
        print(f"\nTest: {test['name']}")
        print(f"Command: {' '.join(test['cmd'])}")
        
        # Run command
        try:
            result = subprocess.run(
                test['cmd'],
                capture_output=True,
                text=True,
                timeout=300,
            )
            
            if result.returncode != 0:
                print(f"  ❌ Command failed with exit code {result.returncode}")
                print(f"  Error: {result.stderr}")
                results.append(False)
                continue
            
            # Check if output file exists
            if not test['output'].exists():
                print(f"  ❌ Output file not created: {test['output']}")
                results.append(False)
                continue
            
            print(f"  ✓ Output file created: {test['output']}")
            
            # Check if meta.json exists
            if not test_meta_json_exists(test['output']):
                print(f"  ❌ meta.json file not created")
                results.append(False)
                continue
            
            print(f"  ✓ meta.json file created")
            
            # Validate meta.json content
            try:
                content = test_meta_json_content(test['output'])
                print(f"  ✓ meta.json content valid")
                print(f"    - id: {content.get('id')}")
                print(f"    - source: {content.get('source')}")

                # Check expected id
                if content.get('id') != test['expected_id']:
                    print(f"  ❌ Unexpected id: expected '{test['expected_id']}', got '{content.get('id')}'")
                    results.append(False)
                    continue

                # Check expected source
                if content.get('source') != test['expected_source']:
                    print(f"  ❌ Unexpected source: expected '{test['expected_source']}', got '{content.get('source')}'")
                    results.append(False)
                    continue

                print(f"  ✓ All checks passed")
                results.append(True)

            except Exception as e:
                print(f"  ❌ Error validating meta.json: {e}")
                results.append(False)
                
        except subprocess.TimeoutExpired:
            print(f"  ❌ Command timed out")
            results.append(False)
        except Exception as e:
            print(f"  ❌ Unexpected error: {e}")
            results.append(False)
    
    # Summary
    print("\n" + "=" * 80)
    print("Test Summary:")
    passed = sum(results)
    total = len(results)
    print(f"  Passed: {passed}/{total}")
    
    if passed == total:
        print("  ✓ All tests passed!")
        return 0
    else:
        print("  ❌ Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
