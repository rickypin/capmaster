# CapMaster preprocess report

Generated at: 2025-12-02T08:14:43.904387+00:00
Output directory: tests/e2e_output/preprocess_quiet
Steps executed: time-align+dedup -> oneway

## Effective configuration (subset)

- archive_original_files: False
- time_align_enabled: True
- dedup_enabled: True
- oneway_enabled: True
- time_align_allow_empty: False
- oneway_ack_threshold: 20

## File comparison

| Original path | Final path | Packets (orig) | Packets (final) | First ts (orig) | Last ts (orig) | First ts (final) | Last ts (final) | Archived |
| --- | --- | ---:| ---:| ---:| ---:| ---:| ---:| --- |
| test.pcap | test.ready.pcap | 59000 | 59000 | 2025-11-24 03:30:00.060152Z | 2025-11-24 03:33:59.992691Z | 2025-11-24 03:30:00.060152Z | 2025-11-24 03:33:59.992691Z | no |