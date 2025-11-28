# Resources

This directory hosts small, version-controlled assets that are required at
runtime or by helper scripts:

- `services.txt` – Sample service list consumed by `capmaster topology`,
  `scripts/test_input_scenarios.sh`, and regression utilities. Pass it to CLI
  commands via `--service-list resources/services.txt`.
- `pipeline_match_test.yaml` – Minimal pipeline template that wires match and
  topology steps together for local validation.

Add any future reference configurations or lookup tables here instead of
keeping ad-hoc copies under `artifacts/`.

