#!/bin/bash
# Examples of using the match plugin with sampling control

# Example 1: Default behavior (sampling kicks in at 1000 connections, keeps 50%)
echo "=== Example 1: Default Behavior ==="
capmaster match -i captures/ -o results_default.txt

# Example 2: Disable sampling completely (process all connections)
echo "=== Example 2: No Sampling ==="
capmaster match -i captures/ --no-sampling -o results_no_sampling.txt

# Example 3: Increase threshold to 5000 (only sample if > 5000 connections)
echo "=== Example 3: Higher Threshold ==="
capmaster match -i captures/ --sampling-threshold 5000 -o results_high_threshold.txt

# Example 4: More aggressive sampling (keep only 30%)
echo "=== Example 4: Aggressive Sampling ==="
capmaster match -i captures/ --sampling-rate 0.3 -o results_aggressive.txt

# Example 5: Conservative sampling (keep 80%)
echo "=== Example 5: Conservative Sampling ==="
capmaster match -i captures/ --sampling-rate 0.8 -o results_conservative.txt

# Example 6: Combined - high threshold with conservative rate
echo "=== Example 6: Combined Parameters ==="
capmaster match -i captures/ \
  --sampling-threshold 10000 \
  --sampling-rate 0.7 \
  -o results_combined.txt

# Example 7: No sampling with endpoint statistics
echo "=== Example 7: No Sampling + Endpoint Stats ==="
capmaster match -i captures/ \
  --no-sampling \
  --endpoint-stats \
  --endpoint-stats-output endpoint_stats.txt \
  -o results_with_stats.txt

# Example 8: Custom sampling with other match options
echo "=== Example 8: Full Configuration ==="
capmaster match -i captures/ \
  --sampling-threshold 2000 \
  --sampling-rate 0.6 \
  --threshold 0.70 \
  --match-mode one-to-many \
  --bucket server \
  --endpoint-stats \
  -o results_full.txt

# Example 9: Verbose mode to see sampling details
echo "=== Example 9: Verbose Mode ==="
capmaster -v match -i captures/ \
  --sampling-threshold 1500 \
  --sampling-rate 0.5 \
  -o results_verbose.txt

# Example 10: Header-only mode with no sampling
echo "=== Example 10: Header-Only + No Sampling ==="
capmaster match -i captures/ \
  --mode header \
  --no-sampling \
  -o results_header_no_sampling.txt

