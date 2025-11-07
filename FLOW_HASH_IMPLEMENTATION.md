# Flow Hash Implementation

## Overview

The flow hash implementation in `capmaster/plugins/compare/flow_hash.py` calculates a directional hash for TCP connections using the SipHash-1-3 algorithm.

## Key Characteristics

### Directional Hash (NOT Bidirectional)

**Important**: This implementation produces a **directional** hash, meaning:
- `hash(A→B) ≠ hash(B→A)` in most cases
- The hash value depends on the order of endpoints (source/destination)
- This is useful for distinguishing client-server directionality

### Algorithm Details

The implementation uses:
- **SipHash-1-3** with multi-message support
- **Fixed key**: `b"\x00" * 16` (16 zero bytes) for reproducibility
- **Special message structure** with IP address length markers

## Message Structure

The hash is calculated over 10 messages in sequence:

1. **Port 1** (2 bytes, big-endian)
2. **Port 2** (2 bytes, big-endian)
3. **IP length marker 1** (8 bytes, little-endian, value=0)
4. **IP length marker 2** (8 bytes, little-endian, value=4)
5. **IP address 1** (4 bytes, packed IPv4)
6. **IP length marker 3** (8 bytes, little-endian, value=0)
7. **IP length marker 4** (8 bytes, little-endian, value=4)
8. **IP address 2** (4 bytes, packed IPv4)
9. **Fixed value** (8 bytes, little-endian, value=1)
10. **Protocol** (1 byte, big-endian, default=6 for TCP)

## Normalization Logic

The algorithm normalizes the input to ensure consistent ordering:

1. **Port comparison**: Ports are compared as little-endian integers
   - If `port1_le <= port2_le`, swap ports and set `flow_side = RHS>LHS`
   - Otherwise, keep original order and set `flow_side = LHS>=RHS`

2. **IP address swap** (conditional):
   - After port swap, if `msg1 < msg2` (byte comparison) OR `msg3 < msg4`
   - Then swap IP addresses and their length markers

## Usage Examples

### Basic Usage

```python
from capmaster.plugins.compare.flow_hash import calculate_flow_hash

# Calculate flow hash
hash_val, flow_side = calculate_flow_hash(
    src_ip="8.67.2.125",
    dst_ip="8.42.96.45",
    src_port=26302,
    dst_port=35101,
    protocol=6  # TCP
)

print(f"Flow hash: {hash_val}")
print(f"Flow side: {flow_side}")
# Output:
# Flow hash: -1173584886679544929
# Flow side: FlowSide.LHS_GE_RHS
```

### Using Connection Wrapper

```python
from capmaster.plugins.compare.flow_hash import calculate_connection_flow_hash

# Calculate flow hash using client/server terminology
hash_val, flow_side = calculate_connection_flow_hash(
    client_ip="8.67.2.125",
    server_ip="8.42.96.45",
    client_port=26302,
    server_port=35101
)
```

### Formatting for Display

```python
from capmaster.plugins.compare.flow_hash import format_flow_hash

formatted = format_flow_hash(hash_val, flow_side)
print(formatted)
# Output: -1173584886679544929 (LHS>=RHS)
```

## Integration with Compare Plugin

The flow hash is integrated into the compare plugin and can be displayed using the `--show-flow-hash` flag:

```bash
python -m capmaster.cli compare -i <directory> --show-flow-hash
```

Example output:
```
No.    Stream ID    Client IP:Port            Server IP:Port            Packets    Flow Hash                     
----------------------------------------------------------------------------------------------------
1      42           10.3.36.141:29842         111.203.2.194:443         27         -9098640129435030446 (RHS>LHS)
2      59           10.3.36.141:29904         111.203.2.194:443         27         -6485417390486030619 (LHS>=RHS)
```

## Test Results

The implementation has been tested and verified to match the reference Python implementation:

### Reference Test Case
- **Input**: `8.67.2.125:26302 -> 8.42.96.45:35101`
- **Expected hash**: `-1173584886679544929`
- **Actual hash**: `-1173584886679544929` ✓
- **Match**: ✓

### Directionality Test
The hash correctly produces different values for forward and reverse directions:

```
8.67.2.125:26302 -> 8.42.96.45:35101
  Forward:  -1173584886679544929 (side=LHS>=RHS)
  Reverse:   1845284189879566450 (side=RHS>LHS)
  Different: ✓
```

## Implementation Files

- **Main implementation**: `capmaster/plugins/compare/flow_hash.py`
- **Plugin integration**: `capmaster/plugins/compare/plugin.py`
- **Test files**:
  - `test_new_flow_hash.py` - Reference implementation test
  - `test_flow_hash_integration.py` - Integration test
  - `test_flow_hash_final.py` - Comprehensive test suite
  - `debug_swap_logic.py` - Debug tool for swap logic

## Technical Notes

### SipHash-1-3 Multi-Message Implementation

The SipHash implementation supports processing multiple messages sequentially while maintaining state across message boundaries. This is different from standard SipHash implementations that process a single byte stream.

### Byte Order Considerations

- **Ports**: Stored as big-endian in messages, but compared as little-endian for normalization
- **IP addresses**: Stored in network byte order (big-endian) via `ipaddress.IPv4Address.packed`
- **Length markers**: Stored as little-endian
- **Protocol**: Stored as big-endian

### Return Value

The hash value is returned as a **signed 64-bit integer** (compatible with database `BIGINT` type):
- Range: `-2^63` to `2^63 - 1`
- Conversion: `u64_to_i64()` converts unsigned to signed representation

## Database Integration

The flow hash can be stored in PostgreSQL as:
```sql
flow_hash BIGINT
```

This matches the schema in `kase_134_tcp_stream_extra` table as documented in `TCP_STREAM_EXTRA_REPORT.md`.

## Future Enhancements

Potential improvements:
1. Support for IPv6 addresses
2. Configurable SipHash keys
3. Optional bidirectional mode
4. Performance optimizations for bulk calculations

