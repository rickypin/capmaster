#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

CAPMASTER=(python -m capmaster)
CASE_MULTI_DIR="data/cases/TC-034-5-20211105"
CASE_MULTI_FILE_APP="$CASE_MULTI_DIR/TC-034-5-20211105-O-APP.pcap"
CASE_MULTI_FILE_LB="$CASE_MULTI_DIR/TC-034-5-20211105-O-LoadBalancer.pcap"
CASE_SINGLE_DIR="data/cases/TC-001-1-20160407"
CASE_SINGLE_FILE_A="$CASE_SINGLE_DIR/TC-001-1-20160407-A.pcap"
CASE_SINGLE_FILE_B="$CASE_SINGLE_DIR/TC-001-1-20160407-B.pcap"
HOPS_DIR="data/2hops/aomenjinguanju_10MB"
HOPS_FILE1="$HOPS_DIR/BOC-LTM_20220922170000_10000.pcap"
HOPS_FILE2="$HOPS_DIR/LTM-web_20220922165947_10000.pcap"
SERVICE_LIST="$REPO_DIR/resources/services.txt"
TMP_ROOT="$REPO_DIR/artifacts/tmp/test_input_scenarios"
RUN_ID="$(date +%Y%m%d%H%M%S)"
WORK_DIR="$TMP_ROOT/$RUN_ID"
LOG_FILE="$WORK_DIR/test.log"

mkdir -p "$WORK_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

cleanup() {
  if [[ -z "${KEEP_TEST_ARTIFACTS:-}" ]]; then
    rm -rf "$WORK_DIR"
  else
    echo "KEEP_TEST_ARTIFACTS is set; leaving $WORK_DIR in place" >&2
  fi
}
trap cleanup EXIT

log() {
  echo "[test-inputs] $*"
}

ensure_path() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    echo "Required path not found: $path" >&2
    exit 1
  fi
}

for required_path in \
  "$CASE_MULTI_DIR" \
  "$CASE_MULTI_FILE_APP" \
  "$CASE_MULTI_FILE_LB" \
  "$CASE_SINGLE_FILE_A" \
  "$CASE_SINGLE_FILE_B" \
  "$HOPS_FILE1" \
  "$HOPS_FILE2" \
  "$SERVICE_LIST"
do
  ensure_path "$required_path"
done

SCENARIO=1
next_scenario() {
  log "Scenario $SCENARIO: $1"
  SCENARIO=$((SCENARIO + 1))
}

run_cli() {
  local desc="$1"; shift
  next_scenario "$desc"
  "${CAPMASTER[@]}" "$@"
}

expect_failure() {
  local desc="$1"; shift
  next_scenario "$desc (expect failure)"
  set +e
  "${CAPMASTER[@]}" "$@"
  local status=$?
  set -e
  if [[ $status -eq 0 ]]; then
    echo "Expected failure but command succeeded" >&2
    exit 1
  fi
}

# Analyze plugin scenarios
ANALYZE_MULTI_DIR="$WORK_DIR/analyze_multi"
run_cli "analyze via -i on $CASE_MULTI_DIR" analyze -i "$CASE_MULTI_DIR" --quiet -o "$ANALYZE_MULTI_DIR"
[[ -d "$ANALYZE_MULTI_DIR" ]]

ANALYZE_SINGLE_DIR="$WORK_DIR/analyze_single"
run_cli "analyze via --file1" analyze --file1 "$CASE_MULTI_FILE_APP" --quiet -o "$ANALYZE_SINGLE_DIR"
[[ -d "$ANALYZE_SINGLE_DIR" ]]

ANALYZE_COMMA_DIR="$WORK_DIR/analyze_comma"
run_cli "analyze via comma-separated -i" analyze -i "$CASE_MULTI_FILE_APP,$CASE_MULTI_FILE_LB" --quiet -o "$ANALYZE_COMMA_DIR"
[[ -d "$ANALYZE_COMMA_DIR" ]]

ANALYZE_FILES_DIR="$WORK_DIR/analyze_files_args"
run_cli "analyze via multiple --fileN" analyze \
  --file1 "$CASE_MULTI_FILE_APP" \
  --file2 "$CASE_MULTI_FILE_LB" \
  --file3 "$CASE_SINGLE_FILE_A" \
  --quiet -o "$ANALYZE_FILES_DIR"
[[ -d "$ANALYZE_FILES_DIR" ]]

EMPTY_INPUT="$WORK_DIR/empty_input"
mkdir -p "$EMPTY_INPUT"
run_cli "analyze allow-no-input on empty directory" analyze -i "$EMPTY_INPUT" --allow-no-input --quiet -o "$WORK_DIR/analyze_empty"

expect_failure "analyze fails when only --file2 provided" analyze --file2 "$CASE_MULTI_FILE_LB" --quiet -o "$WORK_DIR/analyze_invalid"

expect_failure "analyze fails when mixing -i and --fileX" analyze -i "$CASE_MULTI_DIR" --file1 "$CASE_MULTI_FILE_APP" --quiet -o "$WORK_DIR/analyze_mix"

# Match plugin scenarios
MATCH_OUTPUT="$WORK_DIR/matched_connections.txt"
run_cli "match via -i for streamdiff" match -i "$HOPS_DIR" -o "$MATCH_OUTPUT"
[[ -f "$MATCH_OUTPUT" ]]

MATCH_FILES_OUTPUT="$WORK_DIR/matched_connections_files.txt"
run_cli "match via --file1/--file2" match --file1 "$HOPS_FILE1" --file2 "$HOPS_FILE2" -o "$MATCH_FILES_OUTPUT"
[[ -f "$MATCH_FILES_OUTPUT" ]]

expect_failure "match requires two files when --allow-no-input not set" match --file1 "$HOPS_FILE1"

run_cli "match allow-no-input with single file" match --file1 "$HOPS_FILE1" --allow-no-input

# Streamdiff scenarios
STREAMDIFF_OUTPUT="$WORK_DIR/streamdiff_report.txt"
run_cli "streamdiff with matched-connections" streamdiff -i "$HOPS_DIR" --matched-connections "$MATCH_OUTPUT" --pair-index 1 --quiet --output "$STREAMDIFF_OUTPUT"
[[ -f "$STREAMDIFF_OUTPUT" ]]

next_scenario "extract stream IDs from matched-report"
STREAM_ID_LINE="$(python - <<'PY' "$STREAMDIFF_OUTPUT"
import re, sys, pathlib
text = pathlib.Path(sys.argv[1]).read_text()
match = re.search(r"Capture A: .*?stream (\d+).*?Capture B: .*?stream (\d+)", text, re.S)
if not match:
    raise SystemExit("Unable to parse stream IDs from streamdiff output")
print(match.group(1), match.group(2))
PY
)"
read -r STREAM_ID_A STREAM_ID_B <<<"$STREAM_ID_LINE"
log "  -> stream IDs: $STREAM_ID_A / $STREAM_ID_B"

STREAMDIFF_STREAM_OUTPUT="$WORK_DIR/streamdiff_stream_ids.txt"
run_cli "streamdiff with explicit stream IDs" \
  streamdiff --file1 "$HOPS_FILE1" --file2 "$HOPS_FILE2" \
  --file1-stream-id "$STREAM_ID_A" --file2-stream-id "$STREAM_ID_B" \
  --output "$STREAMDIFF_STREAM_OUTPUT"
[[ -f "$STREAMDIFF_STREAM_OUTPUT" ]]

expect_failure "streamdiff fails with insufficient --file inputs" streamdiff --file1 "$HOPS_FILE1"

# Preprocess scenarios
PREPROCESS_DIR_OUTPUT="$WORK_DIR/preprocess_dir"
run_cli "preprocess via -i" preprocess -i "$CASE_SINGLE_DIR" --quiet -o "$PREPROCESS_DIR_OUTPUT"
[[ -d "$PREPROCESS_DIR_OUTPUT" ]]

PREPROCESS_FILES_OUTPUT="$WORK_DIR/preprocess_files"
run_cli "preprocess via --file1/--file2" preprocess --file1 "$CASE_SINGLE_FILE_A" --file2 "$CASE_SINGLE_FILE_B" --quiet -o "$PREPROCESS_FILES_OUTPUT"
[[ -d "$PREPROCESS_FILES_OUTPUT" ]]

run_cli "preprocess allow-no-input with empty input" preprocess -i "$EMPTY_INPUT" --allow-no-input --quiet -o "$WORK_DIR/preprocess_empty"

# Topology + comparative analysis scenarios
TOPOLOGY_OUTPUT="$WORK_DIR/topology.txt"
run_cli "topology with matched connections" \
  topology -i "$HOPS_DIR" --matched-connections "$MATCH_OUTPUT" --service-list "$SERVICE_LIST" --quiet --output "$TOPOLOGY_OUTPUT"
[[ -f "$TOPOLOGY_OUTPUT" ]]

COMPARATIVE_SERVICE_OUTPUT="$WORK_DIR/comparative_service.txt"
run_cli "comparative-analysis service mode" \
  comparative-analysis -i "$HOPS_DIR" --service --topology "$TOPOLOGY_OUTPUT" --output "$COMPARATIVE_SERVICE_OUTPUT"
[[ -f "$COMPARATIVE_SERVICE_OUTPUT" ]]

COMPARATIVE_CONN_OUTPUT="$WORK_DIR/comparative_connections.txt"
run_cli "comparative-analysis matched-connections mode" \
  comparative-analysis -i "$HOPS_DIR" --matched-connections "$MATCH_OUTPUT" --top-n 5 --output "$COMPARATIVE_CONN_OUTPUT"
[[ -f "$COMPARATIVE_CONN_OUTPUT" ]]

# Pipeline scenarios
PIPELINE_INPUT_DIR="$WORK_DIR/pipeline_from_input"
run_cli "run pipeline_standard with -i" \
  run-pipeline -c examples/pipeline_standard.yaml -i "$HOPS_DIR" -o "$PIPELINE_INPUT_DIR" --quiet
[[ -d "$PIPELINE_INPUT_DIR" ]]

PIPELINE_FILE_DIR="$WORK_DIR/pipeline_from_files"
run_cli "run pipeline_standard with --file1/--file2" \
  run-pipeline -c examples/pipeline_standard.yaml --file1 "$HOPS_FILE1" --file2 "$HOPS_FILE2" -o "$PIPELINE_FILE_DIR" --quiet
[[ -d "$PIPELINE_FILE_DIR" ]]

PIPELINE_SINGLE_DIR="$WORK_DIR/pipeline_single"
run_cli "run single-input pipeline with allow-no-input step" \
  run-pipeline -c examples/pipeline_single_input.yaml --file1 "$CASE_SINGLE_FILE_A" -o "$PIPELINE_SINGLE_DIR" --quiet
[[ -d "$PIPELINE_SINGLE_DIR" ]]

expect_failure "pipeline rejects mixed -i and --file inputs" \
  run-pipeline -c examples/pipeline_standard.yaml -i "$HOPS_DIR" --file1 "$HOPS_FILE1" -o "$WORK_DIR/pipeline_invalid"

log "All scenarios completed successfully. Logs stored at $LOG_FILE"
