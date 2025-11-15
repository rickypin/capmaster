#!/usr/bin/env python3
"""Manual regression script to verify compare command generates meta.json and uses markdown format.

NOTE:
- This is a standalone script and is not part of the automated pytest suite.
- It depends on local PCAP files under cases/dbs_20251028-Masked.
"""

import json
import subprocess
import sys
from pathlib import Path


def test_compare_command():
    """Test compare command with meta.json generation."""
    
    # Test command
    cmd = [
        "capmaster", "compare",
        "--file1", "cases/dbs_20251028-Masked/B_processed.pcap",
        "--file1-pcapid", "1",
        "--file2", "cases/dbs_20251028-Masked/A_processed.pcap",
        "--file2-pcapid", "0",
        "--show-flow-hash",
        "--matched-only",
        "--match-mode", "one-to-many",
        "-o", "tmp/packet_differences.md"
    ]
    
    print("=" * 80)
    print("Testing Compare Command with Meta.json Generation")
    print("=" * 80)
    print()
    
    # Run command
    print("Running command:")
    print(" ".join(cmd))
    print()
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"❌ Command failed with return code {result.returncode}")
        print(f"STDERR: {result.stderr}")
        return False
    
    print("✓ Command executed successfully")
    print()
    
    # Check output file
    output_file = Path("tmp/packet_differences.md")
    if not output_file.exists():
        print(f"❌ Output file not found: {output_file}")
        return False
    
    print(f"✓ Output file exists: {output_file}")
    
    # Check meta.json file
    meta_file = Path("tmp/packet_differences.meta.json")
    if not meta_file.exists():
        print(f"❌ Meta.json file not found: {meta_file}")
        return False
    
    print(f"✓ Meta.json file exists: {meta_file}")
    print()
    
    # Verify meta.json content
    with open(meta_file, 'r', encoding='utf-8') as f:
        meta_content = json.load(f)
    
    print("Meta.json content:")
    print(json.dumps(meta_content, indent=2, ensure_ascii=False))
    print()
    
    # Verify required fields
    if "id" not in meta_content:
        print("❌ Missing 'id' field in meta.json")
        return False
    
    if meta_content["id"] != "packet_differences":
        print(f"❌ Incorrect 'id' value: {meta_content['id']} (expected: packet_differences)")
        return False
    
    if "source" not in meta_content:
        print("❌ Missing 'source' field in meta.json")
        return False
    
    if meta_content["source"] != "basic":
        print(f"❌ Incorrect 'source' value: {meta_content['source']} (expected: basic)")
        return False
    
    print("✓ Meta.json content is correct")
    print()
    
    # Check markdown format in output file
    with open(output_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for markdown title
    if not content.startswith("## "):
        print("❌ Output file does not start with markdown title (## )")
        return False
    
    print("✓ Output file starts with markdown title")
    
    # Check for code block
    if "```text" not in content:
        print("❌ Output file does not contain code block start marker (```text)")
        return False
    
    print("✓ Output file contains code block start marker")
    
    if not content.rstrip().endswith("```"):
        print("❌ Output file does not end with code block end marker (```)")
        return False
    
    print("✓ Output file ends with code block end marker")
    print()
    
    # Show first few lines of output
    print("First 20 lines of output file:")
    print("-" * 80)
    lines = content.split('\n')
    for i, line in enumerate(lines[:20], 1):
        print(f"{i:3}: {line}")
    print("-" * 80)
    print()
    
    print("=" * 80)
    print("✅ All tests passed!")
    print("=" * 80)
    
    return True


if __name__ == "__main__":
    success = test_compare_command()
    sys.exit(0 if success else 1)

