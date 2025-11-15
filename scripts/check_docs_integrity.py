"""Simple checks for documentation structure consistency.

This script is intended to be run from the repository root.
It performs lightweight checks on the docs/ directory:

1. Verify that Markdown paths referenced from docs/README.md
   using the pattern ``(docs/XXX.md)`` actually exist.
2. List Markdown files in docs/ that are not mentioned by name
   in docs/README.md (informational only).

Exit code is non-zero only when docs/README.md references
missing files, so it is safe to hook into CI as a guard.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys


DOCS_DIR = Path("docs")
README_PATH = DOCS_DIR / "README.md"


def find_missing_doc_paths(readme_text: str) -> list[str]:
    """Return doc paths like ``docs/XXX.md`` that do not exist.

    The function looks for Markdown links whose target starts with
    ``docs/`` and ends with ``.md`` (e.g. ``(docs/FOO.md)``).
    """
    pattern = re.compile(r"\((docs/[^)]+\.md)\)")
    paths = sorted({match.group(1) for match in pattern.finditer(readme_text)})
    missing = [p for p in paths if not Path(p).exists()]
    return missing


def find_unreferenced_docs(readme_text: str) -> list[str]:
    """Return Markdown files in docs/ not mentioned by name in README.

    This is meant as an informational hint rather than a hard error,
    because some technical or historical documents might intentionally
    be left out of the main index.
    """
    md_files = {p.name for p in DOCS_DIR.glob("*.md") if p.name != "README.md"}
    referenced = {name for name in md_files if name in readme_text}
    unreferenced = sorted(md_files - referenced)
    return unreferenced


def main() -> int:
    """Run documentation checks and return an appropriate exit code."""
    if not README_PATH.exists():
        print("docs/README.md not found", file=sys.stderr)
        return 1

    readme_text = README_PATH.read_text(encoding="utf-8")

    missing_paths = find_missing_doc_paths(readme_text)
    unreferenced_docs = find_unreferenced_docs(readme_text)

    exit_code = 0

    if missing_paths:
        exit_code = 1
        print("Missing documentation paths referenced from docs/README.md:", file=sys.stderr)
        for path_str in missing_paths:
            print(f"  - {path_str}", file=sys.stderr)
        print(file=sys.stderr)

    if unreferenced_docs:
        # Informational only; do not change exit code.
        print("Markdown files in docs/ not referenced by docs/README.md (informational):", file=sys.stderr)
        for name in unreferenced_docs:
            print(f"  - {name}", file=sys.stderr)
        print(file=sys.stderr)

    if exit_code == 0:
        print("Documentation structure check passed.", file=sys.stderr)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

