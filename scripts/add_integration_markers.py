#!/usr/bin/env python3
"""
Script to add @pytest.mark.integration to integration test files.
"""

import re
import sys
from pathlib import Path


def is_integration_test_file(file_path: Path) -> bool:
    """Check if file is an integration test file."""
    # Check filename
    if 'integration' in file_path.name.lower():
        return True
    
    # Check content
    content = file_path.read_text(encoding='utf-8')
    
    # Look for integration test indicators
    indicators = [
        'class.*Integration',
        'subprocess.run',
        'CliRunner',
        'real PCAP',
        'test case',
        'cases/',
    ]
    
    for indicator in indicators:
        if re.search(indicator, content, re.IGNORECASE):
            return True
    
    return False


def add_integration_marker(file_path: Path) -> bool:
    """Add @pytest.mark.integration to test classes in file."""
    content = file_path.read_text(encoding='utf-8')
    lines = content.splitlines(keepends=True)
    
    modified = False
    new_lines = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        
        # Check if this is a test class definition
        if re.match(r'^\s*class\s+Test\w+.*:', line):
            # Check if marker already exists
            has_marker = False
            if i > 0:
                prev_line = lines[i-1].strip()
                if '@pytest.mark.integration' in prev_line:
                    has_marker = True
            
            if not has_marker:
                # Get indentation
                indent = len(line) - len(line.lstrip())
                marker_line = ' ' * indent + '@pytest.mark.integration\n'
                new_lines.append(marker_line)
                modified = True
        
        new_lines.append(line)
        i += 1
    
    if modified:
        file_path.write_text(''.join(new_lines), encoding='utf-8')
    
    return modified


def main():
    """Main function."""
    # Find integration test files
    test_files = []
    
    tests_dir = Path('tests')
    if tests_dir.exists():
        test_files.extend(tests_dir.rglob('test_*.py'))
    
    # Filter out legacy and __pycache__
    test_files = [
        f for f in test_files 
        if '__pycache__' not in str(f) and 'legacy' not in str(f)
    ]
    
    integration_files = []
    modified_files = []
    
    for file_path in sorted(test_files):
        if is_integration_test_file(file_path):
            integration_files.append(file_path)
            if add_integration_marker(file_path):
                modified_files.append(file_path)
                print(f"✓ Added markers to: {file_path}")
            else:
                print(f"  Already marked: {file_path}")
    
    print(f"\n{'='*70}")
    print(f"Summary:")
    print(f"  Integration test files found: {len(integration_files)}")
    print(f"  Files modified: {len(modified_files)}")
    print(f"{'='*70}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

