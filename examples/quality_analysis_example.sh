#!/bin/bash
# Example: Network Quality Analysis
#
# This example demonstrates how to use the quality analysis feature
# to analyze network quality metrics for services.

# Example 1: Basic usage with directory input (recommended)
echo "Example 1: Basic quality analysis using directory"
echo "=================================================="
capmaster analyze-quality \
    -i /path/to/pcaps/ \
    --topology topology.txt

# Example 2: Using comma-separated file list
echo ""
echo "Example 2: Using comma-separated file list"
echo "==========================================="
capmaster analyze-quality \
    -i "capture_point_a.pcap,capture_point_b.pcap" \
    --topology topology.txt

# Example 3: Using explicit file specification
echo ""
echo "Example 3: Using explicit file specification"
echo "============================================="
capmaster analyze-quality \
    --file1 capture_point_a.pcap \
    --file2 capture_point_b.pcap \
    --topology topology.txt

# Example 4: Save results to file
echo ""
echo "Example 4: Save results to file"
echo "================================"
capmaster analyze-quality \
    -i /path/to/pcaps/ \
    --topology topology.txt \
    -o quality_report.txt

# Example 5: Complete workflow with match plugin
echo ""
echo "Example 5: Complete workflow with match plugin"
echo "==============================================="

# Step 1: Match connections between capture points
capmaster match \
    -i /path/to/pcaps/ \
    -o matched_connections.txt

# Step 2: Generate topology report from the matched connections
capmaster topology \
    -i /path/to/pcaps/ \
    --matched-connections matched_connections.txt \
    -o topology.txt

# Step 3: Analyze quality metrics
capmaster analyze-quality \
    -i /path/to/pcaps/ \
    --topology topology.txt \
    -o quality_report.txt

echo ""
echo "Results saved to:"
echo "  - Matched connections: matched_connections.txt"
echo "  - Topology: topology.txt"
echo "  - Quality report: quality_report.txt"
