# Match Strategy Priority

## Overview

The match plugin automatically selects the best matching strategy based on the available information in the PCAP files. The strategies are prioritized as follows:

## Priority Order

### 1. F5 Ethernet Trailer (Highest Priority)
- **Accuracy**: 100%
- **Detection**: Automatically detects F5 Ethernet Trailer in both PCAP files
- **Matching**: Uses peer address/port information from F5 trailer
- **Use Case**: When both PCAP files contain F5 Ethernet Trailer
- **Evidence**: `F5_TRAILER(client=<ip>:<port>)`

### 2. TLS Client Hello (Medium Priority)
- **Accuracy**: Very High (99%+)
- **Detection**: Automatically detects TLS Client Hello packets in both PCAP files
- **Matching**: Uses TLS Client Hello random (32 bytes) + session_id
- **Use Case**: When F5 trailer is not available but TLS traffic is present
- **Evidence**: `TLS_CLIENT_HELLO(random=..., session_id=...)`

### 3. Feature-based (Lowest Priority)
- **Accuracy**: High (configurable via threshold)
- **Detection**: Fallback when neither F5 nor TLS is available
- **Matching**: Uses TCP connection features (SYN options, timestamps, ISN, payload hash, etc.)
- **Use Case**: Non-TLS traffic or when F5/TLS detection fails
- **Evidence**: Feature scores and IPID matching

## Automatic Strategy Selection

The match plugin automatically:
1. First checks for F5 Ethernet Trailer in both files
2. If F5 is not available, checks for TLS Client Hello in both files
3. If neither is available, falls back to feature-based matching

No manual configuration is required. The plugin will log which strategy is being used.

## Test Results

### Test Case 1: dbs_1112_2
- **Strategy Used**: F5 Ethernet Trailer
- **Output**: `Matching connections using F5 trailers...`
- **Result**: ✅ Successfully matched using F5 trailer information

### Test Case 2: dbs_1113
- **Strategy Used**: TLS Client Hello
- **Output**: `Matching connections using TLS Client Hello...`
- **Result**: ✅ Successfully matched using TLS Client Hello (F5 not available)

### Test Case 3: dbs_ori
- **Strategy Used**: Feature-based
- **Output**: `Matching connections...` (with `Analyzing server/client roles...`)
- **Result**: ✅ Successfully matched using feature-based matching (neither F5 nor TLS available)

## Benefits

1. **Automatic Adaptation**: No need to manually specify matching mode
2. **Optimal Accuracy**: Always uses the most accurate method available
3. **Graceful Degradation**: Falls back to less accurate methods when needed
4. **Simplified Usage**: Removed `--f5-mode` and `--tls-mode` parameters

