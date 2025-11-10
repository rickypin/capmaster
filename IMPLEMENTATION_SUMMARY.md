# Endpoint Statistics Feature - Implementation Summary

## Overview

Successfully implemented the endpoint statistics feature for the match plugin, which aggregates matched connections by endpoint tuples (client IP, server IP, server port) and displays them in a paired format showing the relationship between files A and B.

## Implementation Details

### 1. New Modules Created

#### `capmaster/plugins/match/server_detector.py`
- **ServerDetector class**: Multi-layer server detection with 4 priority levels
  - Priority 1: SYN packet direction (HIGH confidence)
  - Priority 2: Port number heuristics (HIGH/MEDIUM confidence)
    - Well-known ports (0-1023, HTTP, HTTPS, SSH, etc.)
    - Database ports (MySQL, PostgreSQL, Redis, MongoDB, etc.)
    - System ports (< 1024)
  - Priority 3: Traffic pattern analysis (placeholder for future enhancement)
  - Priority 4: Port number comparison fallback (VERY_LOW confidence)

- **ServerInfo dataclass**: Contains detected server/client information with confidence level and detection method

#### `capmaster/plugins/match/endpoint_stats.py`
- **EndpointTuple dataclass**: Represents (client IP, server IP, server port) - client port excluded
- **EndpointPairStats dataclass**: Paired statistics for files A and B
- **EndpointStatsCollector class**: Collects and aggregates statistics from matched connections
- **format_endpoint_stats()**: Formats output in detailed paired format
- **format_endpoint_stats_table()**: Formats output in compact table format (available but not used by default)

### 2. Plugin Integration

Modified `capmaster/plugins/match/plugin.py`:
- Added two new CLI parameters:
  - `--endpoint-stats`: Enable endpoint statistics generation
  - `--endpoint-stats-output PATH`: Output file for statistics (optional)
- Added `_output_endpoint_stats()` method to generate and output statistics
- Integrated statistics generation into the execution flow

### 3. Features Implemented

✅ **Only counts matched connections**: Processes only successfully matched connection pairs
✅ **Client port removed**: Aggregates by (client IP, server IP, server port) tuple
✅ **Improved server detection**: Multi-layer heuristics with confidence levels
✅ **Paired output format**: Shows endpoint tuples from both files A and B as pairs
✅ **Connection counting**: Displays count of matched connections for each endpoint pair
✅ **Confidence tracking**: Shows average confidence level for server detection
✅ **File output support**: Can output to file or stdout

## Test Results

### Test Case 1: dbs_ori files
```bash
python -m capmaster match \
  -i /Users/ricky/Downloads/dbs_ori/0215-0315_10.64.0.125.pcap,/Users/ricky/Downloads/dbs_ori/idc_appdbdefault_20250910030547.pcap \
  --endpoint-stats
```

**Results**:
- Total unique endpoint pairs: 3
- Total matched connections: 3
- Confidence: VERY_LOW (no SYN packets, ports not in well-known list)

**Output**:
```
[1] Count: 1 | Confidence: VERY_LOW
    File A: Client 10.38.92.45 → Server 10.64.0.125:26303
    File B: Client 10.38.92.45 → Server 10.64.0.125:26303

[2] Count: 1 | Confidence: VERY_LOW
    File A: Client 10.38.92.45 → Server 10.64.0.125:26302
    File B: Client 10.38.92.45 → Server 10.64.0.125:26302

[3] Count: 1 | Confidence: VERY_LOW
    File A: Client 10.38.92.44 → Server 10.64.0.125:26301
    File B: Client 10.38.92.44 → Server 10.64.0.125:26301
```

### Test Case 2: TC-001-1-20160407 files
```bash
python -m capmaster match \
  -i cases/TC-001-1-20160407/TC-001-1-20160407-A.pcap,cases/TC-001-1-20160407/TC-001-1-20160407-B.pcap \
  --endpoint-stats
```

**Results**:
- Total unique endpoint pairs: 1
- Total matched connections: 63
- Confidence: HIGH (SYN packets available)

**Output**:
```
[1] Count: 63 | Confidence: HIGH
    File A: Client 17.17.17.45 → Server 10.30.50.101:6096
    File B: Client 17.17.17.45 → Server 10.0.6.33:6096
```

This demonstrates excellent aggregation: 63 individual matched connections with different client ports were correctly aggregated into a single endpoint pair.

## Usage Examples

### Basic usage (output to stdout)
```bash
python -m capmaster match -i file1.pcap,file2.pcap --endpoint-stats
```

### Output to file
```bash
python -m capmaster match -i file1.pcap,file2.pcap --endpoint-stats --endpoint-stats-output stats.txt
```

### Combined with other match options
```bash
python -m capmaster match \
  -i file1.pcap,file2.pcap \
  --threshold 0.7 \
  --match-mode one-to-many \
  --endpoint-stats \
  --endpoint-stats-output stats.txt
```

## Output Format

The output includes:
1. **Header**: File names and summary statistics
2. **Endpoint Pairs**: Detailed list of paired endpoints with:
   - Count: Number of matched connections
   - Confidence: Server detection confidence level
   - File A endpoint: Client IP → Server IP:Port
   - File B endpoint: Client IP → Server IP:Port

Example:
```
================================================================================
Endpoint Statistics (Matched Connections Only)
================================================================================

File A: TC-001-1-20160407-A.pcap
File B: TC-001-1-20160407-B.pcap

Total unique endpoint pairs: 1
Total matched connections: 63

Endpoint Pairs:
--------------------------------------------------------------------------------

[1] Count: 63 | Confidence: HIGH
    File A: Client 17.17.17.45 → Server 10.30.50.101:6096
    File B: Client 17.17.17.45 → Server 10.0.6.33:6096

================================================================================
```

## Server Detection Confidence Levels

- **HIGH**: SYN packet direction or well-known port match
- **MEDIUM**: Database port or system port (< 1024) match
- **LOW**: Traffic pattern analysis (not yet implemented)
- **VERY_LOW**: Port number comparison fallback
- **UNKNOWN**: Unable to determine

## Key Design Decisions

1. **Frozen dataclass for EndpointTuple**: Ensures immutability and allows use as dictionary key
2. **Conservative confidence**: Uses minimum confidence of both connections in a match
3. **Average confidence calculation**: Aggregates confidence across multiple matches
4. **Detailed format by default**: Provides clear paired relationship (table format available but not default)
5. **Separate output option**: Allows endpoint stats to be saved separately from match results

## Files Modified

1. `capmaster/plugins/match/plugin.py` - Added CLI parameters and integration
2. Created `capmaster/plugins/match/server_detector.py` - Server detection logic
3. Created `capmaster/plugins/match/endpoint_stats.py` - Statistics collection and formatting

## Backward Compatibility

✅ **Fully backward compatible**: New parameters are optional flags
✅ **No changes to existing behavior**: Default behavior unchanged
✅ **No changes to existing algorithms**: Match algorithm remains identical

## Future Enhancements

Potential improvements for future versions:

1. **Traffic pattern analysis**: Implement Priority 3 detection using packet-level data
2. **Configurable port lists**: Allow users to specify custom well-known ports
3. **CSV/JSON output**: Add alternative output formats for easier parsing
4. **Statistics filtering**: Add options to filter by confidence level or connection count
5. **Bidirectional analysis**: Detect asymmetric routing scenarios
6. **Port role learning**: Learn server ports from SYN packets in the dataset

## Conclusion

The endpoint statistics feature has been successfully implemented and tested. It provides valuable insights into connection patterns by aggregating matched connections and showing the paired relationship between capture points, while maintaining full backward compatibility with existing functionality.

