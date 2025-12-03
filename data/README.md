# Data Assets

This directory groups all large or external datasets consumed by CapMaster:

- `2hops/` – Symlink to dual-capture benchmark cases.
- `cases/` – Local directory with curated regression inputs.
- `preprocess_cases/` – Large troubleshooting datasets for preprocess tests.
- `sample_captures/` – Symlink to miscellaneous sample captures.

All entries are ignored by Git to keep the repository lightweight. Create the
symlinks as needed on your workstation:

```bash
ln -s /path/to/your/2hops data/2hops
ln -s /path/to/your/sample_captures data/sample_captures
```

Feel free to add additional symlinks or small sample files under `data/`; just
document them here when they are required by scripts or tests.

