#!/bin/bash
# Example script to run match commands and generate meta.json files
# This script demonstrates the four commands that generate meta.json files

set -e  # Exit on error

# Configuration
INPUT_DIR="data/2hops/dbs_1112_2/"
OUTPUT_DIR="tmp"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "=========================================="
echo "Running Match Commands with Meta.json"
echo "=========================================="
echo ""

# Command 1: Match connections
echo "1. Running match command..."
capmaster match -i "$INPUT_DIR" -o "$OUTPUT_DIR/matched_connections.txt"
echo "   ✓ Generated: $OUTPUT_DIR/matched_connections.txt"
echo "   ✓ Generated: $OUTPUT_DIR/matched_connections.meta.json"
echo ""

# Command 2: Topology analysis
echo "2. Running topology analysis..."
capmaster topology -i "$INPUT_DIR" --matched-connections "$OUTPUT_DIR/matched_connections.txt" -o "$OUTPUT_DIR/topology.txt"
echo "   ✓ Generated: $OUTPUT_DIR/topology.txt"
echo "   ✓ Generated: $OUTPUT_DIR/topology.meta.json"
echo ""

# Command 3: Comparative analysis - service level
echo "3. Running comparative analysis (service level)..."
capmaster comparative-analysis -i "$INPUT_DIR" --service --topology "$OUTPUT_DIR/topology.txt" -o "$OUTPUT_DIR/service-network-quality.txt"
echo "   ✓ Generated: $OUTPUT_DIR/service-network-quality.txt"
echo "   ✓ Generated: $OUTPUT_DIR/service-network-quality.meta.json"
echo ""

# Command 4: Comparative analysis - connection pairs
echo "4. Running comparative analysis (connection pairs)..."
capmaster comparative-analysis -i "$INPUT_DIR" --matched-connections "$OUTPUT_DIR/matched_connections.txt" --top-n 10 -o "$OUTPUT_DIR/top10-poor-network-quality-session-pairs.txt"
echo "   ✓ Generated: $OUTPUT_DIR/top10-poor-network-quality-session-pairs.txt"
echo "   ✓ Generated: $OUTPUT_DIR/top10-poor-network-quality-session-pairs.meta.json"
echo ""

echo "=========================================="
echo "All commands completed successfully!"
echo "=========================================="
echo ""

# Display meta.json files
echo "Meta.json files content:"
echo "=========================================="
for meta_file in "$OUTPUT_DIR"/*.meta.json; do
    if [ -f "$meta_file" ]; then
        echo ""
        echo "File: $(basename "$meta_file")"
        echo "---"
        cat "$meta_file"
        echo ""
    fi
done
