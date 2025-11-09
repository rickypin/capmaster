#!/usr/bin/env python3
"""
Script to add 'from __future__ import annotations' to Python files.

This fixes Python 3.9 compatibility issues with PEP 604 union syntax (Type | None).
"""

import sys
from pathlib import Path


def needs_future_annotations(file_path: Path) -> bool:
    """Check if file needs the future annotations import."""
    content = file_path.read_text(encoding='utf-8')
    
    # Already has the import
    if 'from __future__ import annotations' in content:
        return False
    
    # Check for PEP 604 union syntax or generic type hints
    indicators = [
        ' | None',
        'Path | ',
        'dict | ',
        'str | ',
        'int | ',
        'list[',
        'dict[',
        'set[',
        'tuple[',
    ]
    
    return any(indicator in content for indicator in indicators)


def add_future_annotations(file_path: Path) -> bool:
    """Add 'from __future__ import annotations' to a Python file."""
    content = file_path.read_text(encoding='utf-8')
    lines = content.splitlines(keepends=True)
    
    # Find the position to insert the import
    insert_pos = 0
    in_docstring = False
    docstring_char = None
    
    for i, line in enumerate(lines):
        stripped = line.strip()
        
        # Handle module docstring
        if i == 0 and (stripped.startswith('"""') or stripped.startswith("'''")):
            docstring_char = stripped[:3]
            if stripped.count(docstring_char) >= 2:
                # Single-line docstring
                insert_pos = i + 1
            else:
                # Multi-line docstring starts
                in_docstring = True
            continue
        
        if in_docstring:
            if docstring_char in line:
                in_docstring = False
                insert_pos = i + 1
            continue
        
        # Skip shebang
        if stripped.startswith('#!'):
            insert_pos = i + 1
            continue
        
        # Skip encoding declarations
        if stripped.startswith('#') and ('coding' in stripped or 'encoding' in stripped):
            insert_pos = i + 1
            continue
        
        # Skip empty lines and comments at the top
        if not stripped or stripped.startswith('#'):
            insert_pos = i + 1
            continue
        
        # Found first real code
        break
    
    # Insert the import
    import_line = 'from __future__ import annotations\n'
    
    # Add blank line before if needed
    if insert_pos > 0 and lines[insert_pos - 1].strip():
        import_line = '\n' + import_line
    
    # Add blank line after if needed
    if insert_pos < len(lines) and lines[insert_pos].strip() and not lines[insert_pos].startswith('import'):
        import_line = import_line + '\n'
    
    lines.insert(insert_pos, import_line)
    
    # Write back
    file_path.write_text(''.join(lines), encoding='utf-8')
    return True


def main():
    """Main function."""
    # Get all Python files
    files_to_check = []
    
    # Check capmaster directory
    capmaster_dir = Path('capmaster')
    if capmaster_dir.exists():
        files_to_check.extend(capmaster_dir.rglob('*.py'))
    
    # Check tests directory
    tests_dir = Path('tests')
    if tests_dir.exists():
        files_to_check.extend(tests_dir.rglob('*.py'))
    
    # Filter out __pycache__
    files_to_check = [f for f in files_to_check if '__pycache__' not in str(f)]
    
    modified_files = []
    skipped_files = []
    
    for file_path in sorted(files_to_check):
        if needs_future_annotations(file_path):
            try:
                add_future_annotations(file_path)
                modified_files.append(file_path)
                print(f"✓ Modified: {file_path}")
            except Exception as e:
                print(f"✗ Error processing {file_path}: {e}", file=sys.stderr)
        else:
            skipped_files.append(file_path)
    
    print(f"\n{'='*70}")
    print(f"Summary:")
    print(f"  Modified: {len(modified_files)} files")
    print(f"  Skipped:  {len(skipped_files)} files")
    print(f"  Total:    {len(files_to_check)} files")
    print(f"{'='*70}")
    
    return 0 if not modified_files else 0


if __name__ == '__main__':
    sys.exit(main())

