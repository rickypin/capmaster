---
name: capmaster-topology-streamdiff
description: Instructions for using Capmaster's topology and streamdiff plugins to describe network relationships and compare mirrored TCP streams.
---

# Capmaster Topology & StreamDiff Skill

This skill teaches agents how to inspect PCAP captures with Capmaster whenever they need to explain network topology or highlight per-connection packet deltas.

## When to use this skill
- A user asks for host/service relationships, path visualizations, or “what talks to what” summaries sourced from one or two captures.
- You must compare how the same TCP connection behaves at two capture points to explain packet loss, filtering, or latency shifts.
- Evidence already resides under `resources/`, and the workflow must stay within repo-relative paths (no `..`).

## Required files & prep work
1. Stage the relevant PCAPs inside `resources/pcap/uploaded/`; keep only the inputs needed for this task.
2. (Optional) Run `capmaster match` first and save `resources/evidence/matched_connections.md` so that dual-capture commands can align flows.
3. Maintain the canonical service map at `resources/services.txt` for consistent naming in topology output.
4. Create `resources/evidence/` to store scratch and shareable outputs: `mkdir -p resources/evidence`.

## How to use this skill
Follow the branch that matches the question you need to answer.

### Topology workflows
Use `capmaster topology` to describe how clients and services interact.

#### Single-point topology
```
capmaster topology -i resources/pcap/uploaded/ \
  --service-list resources/services.txt \
  -o resources/evidence/topology_single.md
```

1. Ensure only one PCAP sits in the input directory, or pass `--single-file resources/pcap/uploaded/<file>.pcap` to pin the source.
2. Provide the service list so Capmaster can collapse ports into human-readable service names.
3. Save the report to `resources/evidence/` and summarize notable client/service groupings in your answer.

#### Two-point topology
```
capmaster topology -i resources/pcap/uploaded/ \
  --matched-connections resources/evidence/matched_connections.md \
  --service-list resources/services.txt \
  -o resources/evidence/topology_double.md
```

1. Confirm the directory holds exactly two complementary captures for the same scenario.
2. Supply the matched connections file to keep client/server pairs aligned between vantage points.
3. If matches are empty but you still need partial insight, set `--empty-match-behavior fallback-single`; otherwise keep the default `error` to expose mismatches.
4. Use `--file1` / `--file2` when you need deterministic ordering or the directory contains additional samples.

### Streamdiff workflows
`capmaster streamdiff` highlights per-packet differences for one TCP connection captured at two locations.

#### Matched-connections path (preferred)
```
capmaster streamdiff -i resources/pcap/uploaded/ \
  --matched-connections resources/evidence/matched_connections.md \
  --pair-index 1 \
  -o resources/evidence/streamdiff_pair1.md
```

1. Choose the target pair index from the matched-connections file (1-based).
2. Run the command and keep the output artifact under `resources/evidence/`. It separates `Only in File1` vs `Only in File2` packets using IP IDs or sequence clues.
3. Iterate pair indices when you need multiple comparisons; name each report descriptively.

#### Explicit stream IDs (fallback)
```
capmaster streamdiff -i resources/pcap/uploaded/ \
  --file1-stream-id 7 \
  --file2-stream-id 33 \
  -o resources/evidence/streamdiff_7_33.md
```

1. Use Wireshark/TShark to determine the correct `tcp.stream` IDs for both files.
2. Pass `--file1` / `--file2` (and `--file1-pcapid` / `--file2-pcapid`) when the directory holds more than two captures.
3. Confirm both streams cover the same 5-tuple; if Capmaster reports “connection not found,” re-check the IDs or regenerate matched connections.

## Quick checklist
- Inputs staged under `resources/pcap/uploaded/`, outputs directed to `resources/evidence/`.
- Run `capmaster match` when dual-capture workflows need aligned connections.
- Keep `resources/services.txt` updated so topology renders friendly names.
- Cite every CLI invocation (command, arguments, output path) in your final response.

## Reference files
- `resources/pcap/uploaded/`: Working directory for single or dual PCAP inputs.
- `resources/evidence/matched_connections.md`: Output from `capmaster match`, consumed by topology and streamdiff.
- `resources/services.txt`: Service dictionary referenced by topology.
- `resources/evidence/*.md`: Default destination for generated reports.
- `reports/analysis/<case>/`: Long-term storage for finalized artifacts.

## Output interpretation
- Mention whether the topology output reflects single or dual capture mode to avoid ambiguity.
- When topology lists `Unknown` services, update `resources/services.txt` or explain the mapping manually.
- For streamdiff, large `Only in File1` sections mean packets never reached the second capture; highlight where the loss or filtering likely occurred.
- If both streamdiff sections are empty, explicitly state that the connection behaved identically at both vantage points.

## Troubleshooting & escalation
- Stick to repo-relative paths: inputs under `resources/`, outputs under `resources/evidence/` (temporary or shareable) or `reports/analysis/` (long-term).
- When Capmaster exits with “No matched connections,” rerun `capmaster match` or pivot to single-point topology/explicit stream IDs.
- If users need topology plus streamdiff, run topology first to scope the services, then drill into the suspicious connection with streamdiff.
- Document every command, arguments, and generated artifact paths so future investigations can replay the steps.

## Keywords
capmaster, topology, streamdiff, tcp stream, packet diff, pcap analysis