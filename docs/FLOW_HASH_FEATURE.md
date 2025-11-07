# Flow Hash Feature

## Overview

The Flow Hash feature provides a bidirectional flow identifier for TCP connections. This feature is particularly useful for:

- Identifying the same connection across different PCAP files
- Grouping packets belonging to the same flow regardless of direction
- Correlating connections in network analysis

## Algorithm

The flow hash algorithm is based on the Rust implementation and provides the following characteristics:

### Key Features

1. **Bidirectional Consistency**: The same hash value is generated for both directions of a flow
2. **5-Tuple Based**: Uses source IP, destination IP, source port, destination port, and protocol
3. **Normalized Ordering**: Endpoints are ordered consistently to ensure bidirectionality

### Calculation Steps

1. **Port Comparison**: Compare source and destination ports to determine initial flow direction
2. **IP Comparison**: If ports are equal, compare IP addresses to determine flow direction
3. **Normalization**: Order the 5-tuple elements based on the determined direction
4. **Hashing**: Hash the ordered elements using MD5 (first 64 bits)

### Flow Side Indicator

The algorithm returns a `FlowSide` indicator along with the hash:

- `LHS_GE_RHS`: Left-hand side (source) >= Right-hand side (destination)
- `RHS_GT_LHS`: Right-hand side (destination) > Left-hand side (source)
- `UNKNOWN`: Unable to determine (should not occur in normal operation)

## Usage

### Command Line

Enable flow hash display in the compare plugin using the `--show-flow-hash` flag:

```bash
# Basic usage
capmaster compare -i /path/to/pcaps/ --show-flow-hash

# With other options
capmaster compare -i /path/to/pcaps/ --show-flow-hash --threshold 0.70 -o results.txt
```

### Output Format

When `--show-flow-hash` is enabled, the output includes:

#### 1. Flow Hash Summary Section

```
================================================================================
Flow Hash Summary
================================================================================
Connection                                                   Flow Hash                 Status         
--------------------------------------------------------------------------------
192.168.1.100:54321 <-> 10.0.0.1:80                         a1b2c3d4e5f67890 (LHS>=RHS) Identical      
192.168.1.101:54322 <-> 10.0.0.1:443                        b2c3d4e5f6789012 (RHS>LHS)  3 diffs        
...
```

#### 2. Per-Connection Summary (with differences)

```
================================================================================
Per-Connection Summary
================================================================================
Connection ID                                      Score      Diffs      Flow Hash           
--------------------------------------------------------------------------------
192.168.1.100:54321 <-> 10.0.0.1:80               0.95       3          a1b2c3d4e5f67890 (LHS>=RHS)
...
```

### Programmatic Usage

```python
from capmaster.plugins.compare.flow_hash import (
    calculate_flow_hash,
    calculate_connection_flow_hash,
    format_flow_hash,
    FlowSide,
)

# Calculate flow hash from 5-tuple
hash_hex, flow_side = calculate_flow_hash(
    src_ip="192.168.1.100",
    dst_ip="10.0.0.1",
    src_port=54321,
    dst_port=80,
    protocol=6,  # TCP
)

# Calculate flow hash from connection endpoints
hash_hex, flow_side = calculate_connection_flow_hash(
    client_ip="192.168.1.100",
    server_ip="10.0.0.1",
    client_port=54321,
    server_port=80,
)

# Format for display
formatted = format_flow_hash(hash_hex, flow_side)
print(formatted)  # Output: a1b2c3d4e5f67890 (LHS>=RHS)
```

## Implementation Details

### Module: `capmaster/plugins/compare/flow_hash.py`

The flow hash module provides the following functions:

#### `calculate_flow_hash(src_ip, dst_ip, src_port, dst_port, protocol=6)`

Calculate flow hash from a 5-tuple.

**Parameters:**
- `src_ip` (str): Source IP address (IPv4 or IPv6)
- `dst_ip` (str): Destination IP address (IPv4 or IPv6)
- `src_port` (int): Source port number
- `dst_port` (int): Destination port number
- `protocol` (int): IP protocol number (default: 6 for TCP)

**Returns:**
- `tuple[str, FlowSide]`: Hash hex string (16 chars) and flow side indicator

#### `calculate_connection_flow_hash(client_ip, server_ip, client_port, server_port)`

Convenience wrapper for calculating flow hash from connection endpoints.

**Parameters:**
- `client_ip` (str): Client IP address
- `server_ip` (str): Server IP address
- `client_port` (int): Client port number
- `server_port` (int): Server port number

**Returns:**
- `tuple[str, FlowSide]`: Hash hex string (16 chars) and flow side indicator

#### `format_flow_hash(hash_hex, flow_side)`

Format flow hash for display.

**Parameters:**
- `hash_hex` (str): Hash value as hex string
- `flow_side` (FlowSide): Flow side indicator

**Returns:**
- `str`: Formatted string (e.g., "a1b2c3d4e5f67890 (LHS>=RHS)")

## Comparison with Rust Implementation

The Python implementation approximates the Rust version's behavior with the following differences:

### Similarities

1. **Bidirectional consistency**: Both implementations produce the same hash for both directions
2. **Normalization logic**: Same port and IP comparison logic
3. **Flow side indicator**: Same FlowSide enum values

### Differences

1. **Hash Algorithm**: 
   - Rust: Uses `std::collections::hash_map::DefaultHasher`
   - Python: Uses MD5 (first 64 bits)
   
2. **Hash Output**:
   - Rust: Returns `u64` (8-byte integer)
   - Python: Returns 16-character hex string (8 bytes)

3. **Portability**:
   - Rust: DefaultHasher is platform-dependent
   - Python: MD5 is consistent across platforms

### Why MD5?

We chose MD5 for the Python implementation because:

1. **Consistency**: MD5 produces the same output across all platforms
2. **Availability**: Built into Python's standard library
3. **Performance**: Fast enough for this use case
4. **Collision Resistance**: Sufficient for flow identification (not cryptographic use)

**Note**: The hash values will differ between Rust and Python implementations, but both maintain bidirectional consistency within their respective implementations.

## Testing

The flow hash implementation includes comprehensive tests:

```bash
# Run flow hash tests
python -m pytest tests/test_flow_hash.py -v
```

Test coverage includes:
- Bidirectional consistency
- Different connections produce different hashes
- Port-based flow side determination
- IP-based flow side determination (when ports are equal)
- IPv6 support
- Hash formatting
- Protocol differentiation

## Use Cases

### 1. Connection Correlation

Identify the same connection across different PCAP files:

```bash
capmaster compare -i pcaps/ --show-flow-hash -o results.txt
```

### 2. Flow Grouping

Group packets by flow hash for analysis:

```python
from capmaster.plugins.compare.flow_hash import calculate_connection_flow_hash

flows = {}
for connection in connections:
    hash_hex, _ = calculate_connection_flow_hash(
        connection.client_ip,
        connection.server_ip,
        connection.client_port,
        connection.server_port,
    )
    if hash_hex not in flows:
        flows[hash_hex] = []
    flows[hash_hex].append(connection)
```

### 3. Bidirectional Traffic Analysis

Analyze traffic in both directions using the same identifier:

```python
# Forward direction
hash1, side1 = calculate_flow_hash("192.168.1.1", "10.0.0.1", 12345, 80)

# Reverse direction
hash2, side2 = calculate_flow_hash("10.0.0.1", "192.168.1.1", 80, 12345)

assert hash1 == hash2  # Same flow hash
assert side1 != side2  # Different flow sides
```

## Future Enhancements

Potential improvements for the flow hash feature:

1. **Hash Algorithm Options**: Allow users to choose between different hash algorithms
2. **Custom Normalization**: Support custom normalization rules
3. **Flow Hash Export**: Export flow hashes to CSV or JSON format
4. **Flow Hash Filtering**: Filter connections by flow hash pattern
5. **Rust Compatibility Mode**: Option to use the exact Rust algorithm (via FFI or subprocess)

