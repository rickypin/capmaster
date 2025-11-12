#!/bin/bash
# Test script to verify match and compare consistency without using --match-file

set -e

PCAP_DIR="${1:-/Users/ricky/Downloads/2hops/aomenjinguanju/}"

echo "================================================================================"
echo "Testing Match and Compare Consistency (Without --match-file)"
echo "================================================================================"
echo ""
echo "PCAP Directory: $PCAP_DIR"
echo ""

# Run match command and extract stream pairs
echo "Step 1: Running match command..."
MATCH_OUTPUT=$(capmaster match -i "$PCAP_DIR" 2>&1)
echo "✓ Match completed"
echo ""

# Extract match pairs (format: [N] A: IP:PORT <-> IP:PORT)
echo "Match results:"
echo "$MATCH_OUTPUT" | grep -E "^\[[0-9]+\] A:" | head -5
echo "..."
echo ""

# Run compare command and extract stream pairs
echo "Step 2: Running compare command..."
COMPARE_OUTPUT=$(capmaster compare -i "$PCAP_DIR" 2>&1)
echo "✓ Compare completed"
echo ""

# Extract compare stream pairs
echo "Compare stream pairs:"
echo "$COMPARE_OUTPUT" | grep "Stream Pair:" | head -5
echo "..."
echo ""

# Verify consistency for a specific example (Stream 9)
echo "================================================================================"
echo "Verification: Stream 9 Matching"
echo "================================================================================"
echo ""

# Extract match result for connection #10 (Stream 9)
MATCH_CONN=$(echo "$MATCH_OUTPUT" | grep -A 2 "^\[10\]" | grep "B:")
echo "Match command result for connection #10:"
echo "$MATCH_CONN"
echo ""

# Extract compare result for Stream 9
COMPARE_STREAM=$(echo "$COMPARE_OUTPUT" | grep "Stream Pair.*Stream 9")
echo "Compare command result for Stream 9:"
echo "$COMPARE_STREAM"
echo ""

# Extract the stream ID from compare output
COMPARE_STREAM_ID=$(echo "$COMPARE_STREAM" | grep -oE "Compare Stream [0-9]+" | grep -oE "[0-9]+")
echo "Compare matched Stream 9 to Stream $COMPARE_STREAM_ID"
echo ""

# Find the port for this stream in compare output
COMPARE_PORT=$(echo "$COMPARE_OUTPUT" | grep "^10.*$COMPARE_STREAM_ID" | grep -oE "172.100.8.102:[0-9]+" | grep -oE "[0-9]+$")
echo "Stream $COMPARE_STREAM_ID corresponds to port $COMPARE_PORT"
echo ""

# Extract port from match output
MATCH_PORT=$(echo "$MATCH_CONN" | grep -oE "172.100.8.102:[0-9]+" | grep -oE "[0-9]+$")
echo "Match command shows port $MATCH_PORT"
echo ""

# Verify they match
if [ "$MATCH_PORT" = "$COMPARE_PORT" ]; then
    echo "✓ SUCCESS: Match and Compare are consistent!"
    echo "  Both commands matched Stream 9 to the connection with port $MATCH_PORT"
else
    echo "✗ FAILURE: Match and Compare are inconsistent!"
    echo "  Match: port $MATCH_PORT"
    echo "  Compare: port $COMPARE_PORT"
    exit 1
fi

echo ""
echo "================================================================================"
echo "Testing Multiple Runs for Determinism"
echo "================================================================================"
echo ""

# Run match 3 times and check consistency
echo "Running match command 3 times..."
for i in 1 2 3; do
    RESULT=$(capmaster match -i "$PCAP_DIR" 2>&1 | grep -A 1 "^\[10\]" | grep "B:" | grep -oE "172.100.8.102:[0-9]+" | grep -oE "[0-9]+$")
    echo "  Run $i: port $RESULT"
    if [ $i -eq 1 ]; then
        FIRST_RESULT=$RESULT
    elif [ "$RESULT" != "$FIRST_RESULT" ]; then
        echo "✗ FAILURE: Match results are not deterministic!"
        exit 1
    fi
done
echo "✓ Match is deterministic across multiple runs"
echo ""

# Run compare 3 times and check consistency
echo "Running compare command 3 times..."
for i in 1 2 3; do
    STREAM_ID=$(capmaster compare -i "$PCAP_DIR" 2>&1 | grep "Stream Pair.*Stream 9" | grep -oE "Compare Stream [0-9]+" | grep -oE "[0-9]+")
    RESULT=$(capmaster compare -i "$PCAP_DIR" 2>&1 | grep "^10.*$STREAM_ID" | grep -oE "172.100.8.102:[0-9]+" | grep -oE "[0-9]+$")
    echo "  Run $i: Stream $STREAM_ID (port $RESULT)"
    if [ $i -eq 1 ]; then
        FIRST_RESULT=$RESULT
    elif [ "$RESULT" != "$FIRST_RESULT" ]; then
        echo "✗ FAILURE: Compare results are not deterministic!"
        exit 1
    fi
done
echo "✓ Compare is deterministic across multiple runs"
echo ""

echo "================================================================================"
echo "Summary"
echo "================================================================================"
echo ""
echo "✓ Match and Compare produce consistent results"
echo "✓ Both commands are deterministic across multiple runs"
echo "✓ No need to use --match-file for consistency"
echo ""
echo "The stable sorting mechanism ensures that match and compare always"
echo "produce the same connection pairs, even when multiple pairs have"
echo "identical scores."
echo ""

