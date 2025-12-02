#!/bin/bash
# Test script for module selection feature

set -e

echo "========================================="
echo "Module Selection Feature Test Script"
echo "========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test PCAP file
PRIMARY_PCAP="data/cases/V-001/VOIP.pcap"
FALLBACK_PCAP="data/cases_02/V-001/VOIP.pcap"
if [ -f "$PRIMARY_PCAP" ]; then
    TEST_PCAP="$PRIMARY_PCAP"
elif [ -f "$FALLBACK_PCAP" ]; then
    TEST_PCAP="$FALLBACK_PCAP"
else
    echo -e "${RED}✗ Test PCAP file not found under data/cases or data/cases_02${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Test PCAP file found${NC}"
echo ""

# Create temporary directory for test outputs
TEST_DIR=$(mktemp -d)
echo "Test output directory: $TEST_DIR"
echo ""

# Test 1: Single module selection
echo "Test 1: Single module selection (protocol_hierarchy)"
echo "Command: capmaster analyze -i $TEST_PCAP -m protocol_hierarchy -o $TEST_DIR/test1"
python -m capmaster analyze -i "$TEST_PCAP" -m protocol_hierarchy -o "$TEST_DIR/test1" > /dev/null 2>&1

FILE_COUNT=$(ls "$TEST_DIR/test1"/*.txt 2>/dev/null | wc -l | tr -d ' ')
if [ "$FILE_COUNT" -eq "1" ]; then
    echo -e "${GREEN}✓ PASS: Generated 1 output file${NC}"
else
    echo -e "${RED}✗ FAIL: Expected 1 file, got $FILE_COUNT${NC}"
    exit 1
fi
echo ""

# Test 2: Multiple module selection
echo "Test 2: Multiple module selection (protocol_hierarchy + sip_stats)"
echo "Command: capmaster analyze -i $TEST_PCAP -m protocol_hierarchy -m sip_stats -o $TEST_DIR/test2"
python -m capmaster analyze -i "$TEST_PCAP" -m protocol_hierarchy -m sip_stats -o "$TEST_DIR/test2" > /dev/null 2>&1

FILE_COUNT=$(ls "$TEST_DIR/test2"/*.txt 2>/dev/null | wc -l | tr -d ' ')
if [ "$FILE_COUNT" -eq "2" ]; then
    echo -e "${GREEN}✓ PASS: Generated 2 output files${NC}"
else
    echo -e "${RED}✗ FAIL: Expected 2 files, got $FILE_COUNT${NC}"
    exit 1
fi
echo ""

# Test 3: Invalid module name
echo "Test 3: Invalid module name (should fail)"
echo "Command: capmaster analyze -i $TEST_PCAP -m invalid_module -o $TEST_DIR/test3"
if python -m capmaster analyze -i "$TEST_PCAP" -m invalid_module -o "$TEST_DIR/test3" > /dev/null 2>&1; then
    echo -e "${RED}✗ FAIL: Should have failed with invalid module name${NC}"
    exit 1
else
    echo -e "${GREEN}✓ PASS: Correctly rejected invalid module name${NC}"
fi
echo ""

# Test 4: Default behavior (no module selection)
echo "Test 4: Default behavior (all modules)"
echo "Command: capmaster analyze -i $TEST_PCAP -o $TEST_DIR/test4"
python -m capmaster analyze -i "$TEST_PCAP" -o "$TEST_DIR/test4" > /dev/null 2>&1

FILE_COUNT=$(ls "$TEST_DIR/test4"/*.txt 2>/dev/null | wc -l | tr -d ' ')
if [ "$FILE_COUNT" -gt "1" ]; then
    echo -e "${GREEN}✓ PASS: Generated $FILE_COUNT output files (all applicable modules)${NC}"
else
    echo -e "${RED}✗ FAIL: Expected multiple files, got $FILE_COUNT${NC}"
    exit 1
fi
echo ""

# Test 5: Verify output content
echo "Test 5: Verify output content"
PROTOCOL_FILE=$(ls "$TEST_DIR/test1"/*protocol-hierarchy.txt 2>/dev/null | head -1)
if [ -f "$PROTOCOL_FILE" ]; then
    if grep -q "Protocol Hierarchy Statistics" "$PROTOCOL_FILE"; then
        echo -e "${GREEN}✓ PASS: Output file contains expected content${NC}"
    else
        echo -e "${RED}✗ FAIL: Output file missing expected content${NC}"
        exit 1
    fi
else
    echo -e "${RED}✗ FAIL: Protocol hierarchy file not found${NC}"
    exit 1
fi
echo ""

# Test 6: CLI help shows module option
echo "Test 6: CLI help shows module option"
if python -m capmaster analyze --help | grep -q "\-m.*modules"; then
    echo -e "${GREEN}✓ PASS: --modules option appears in help${NC}"
else
    echo -e "${RED}✗ FAIL: --modules option not found in help${NC}"
    exit 1
fi
echo ""

# Cleanup
echo "Cleaning up test directory: $TEST_DIR"
rm -rf "$TEST_DIR"
echo ""

echo "========================================="
echo -e "${GREEN}All tests passed!${NC}"
echo "========================================="
echo ""
echo "Summary:"
echo "  ✓ Single module selection works"
echo "  ✓ Multiple module selection works"
echo "  ✓ Invalid module name is rejected"
echo "  ✓ Default behavior (all modules) works"
echo "  ✓ Output content is correct"
echo "  ✓ CLI help is updated"
echo ""
echo "Feature is ready for use!"

