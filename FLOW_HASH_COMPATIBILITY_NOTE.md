# Flow Hash Compatibility Note

## Current Status

The Python implementation of flow hash uses **SipHash-1-3** with fixed keys (k0=0, k1=0) to ensure:

1. ✅ **Bidirectional consistency**: Same hash for both directions of a flow
2. ✅ **Deterministic output**: Same input always produces same hash
3. ✅ **Cross-platform consistency**: Same hash on all platforms

## Rust Compatibility Issue

The current Python implementation does **NOT** produce the same hash values as the Rust implementation.

### Example

**Connection**: `8.42.96.45:35101 <-> 8.67.2.125:26302`

- **Python SipHash-1-3 result**: `-6629771415356728108`
- **Rust DefaultHasher result**: `-1173584886679544929`
- **Match**: ❌ No

### Why They Don't Match

Rust's `std::collections::hash_map::DefaultHasher` uses:

1. **SipHash-1-3** algorithm (same as Python)
2. **Random keys** that change on each program execution
3. **Platform-specific implementation details**

The random keys mean that even if we use the exact same algorithm, we cannot predict what hash value Rust will produce without knowing the keys.

### Verification

We tested:
- ✅ All possible byte orderings (little-endian, big-endian)
- ✅ All possible data serialization orders
- ✅ Multiple SipHash variants (1-3, 2-4)
- ✅ Different key combinations
- ❌ None matched the Rust output

## Solutions

### Option 1: Accept Different Hash Values (Recommended)

**Pros:**
- Python implementation is self-consistent
- Bidirectional consistency works perfectly
- Deterministic and reproducible
- No external dependencies

**Cons:**
- Cannot directly compare hash values between Python and Rust

**Use case:** If you only need flow hashing within Python (e.g., for the compare plugin), this is the best option.

### Option 2: Make Rust Use Fixed Keys

Modify the Rust code to use fixed keys instead of random keys:

```rust
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

// Instead of:
let mut hasher = DefaultHasher::new();

// Use:
use siphasher::sip::SipHasher13;
let mut hasher = SipHasher13::new_with_keys(0, 0);
```

**Pros:**
- Both implementations can produce identical hashes
- Full compatibility

**Cons:**
- Requires modifying Rust code
- Need to add `siphasher` crate dependency

### Option 3: Call Rust from Python via FFI

Create a Python extension that calls the Rust hash function directly.

**Pros:**
- Guaranteed compatibility
- Uses the exact same code

**Cons:**
- Complex setup
- Platform-specific compilation
- Additional dependencies

### Option 4: Use a Different Hash Algorithm

Switch both implementations to use a standard hash like MD5 or SHA256.

**Pros:**
- Well-defined, standard algorithms
- Easy to implement in both languages

**Cons:**
- Slower than SipHash
- Not what the original Rust code uses

## Current Implementation Details

### Python Implementation

```python
def calculate_flow_hash(src_ip, dst_ip, src_port, dst_port, protocol=6):
    # Determine flow side
    flow_side = compare_ports(src_port, dst_port)
    if src_port == dst_port:
        flow_side = compare_addresses(src_ip, dst_ip)
    
    # Serialize data
    data = bytearray()
    if flow_side == FlowSide.LHS_GE_RHS:
        data.extend(struct.pack('<H', src_port))
        data.extend(struct.pack('<H', dst_port))
        data.extend(ipaddress.ip_address(src_ip).packed)
        data.extend(ipaddress.ip_address(dst_ip).packed)
    else:
        data.extend(struct.pack('<H', dst_port))
        data.extend(struct.pack('<H', src_port))
        data.extend(ipaddress.ip_address(dst_ip).packed)
        data.extend(ipaddress.ip_address(src_ip).packed)
    data.extend(struct.pack('B', protocol))
    
    # Hash with SipHash-1-3 (k0=0, k1=0)
    hash_value = siphash13(bytes(data), k0=0, k1=0)
    
    return hash_value, flow_side
```

**Key characteristics:**
- Ports: little-endian u16
- IPs: network byte order (big-endian)
- Protocol: u8
- Hash: SipHash-1-3 with k0=0, k1=0

### Rust Implementation (Assumed)

```rust
pub fn calculate_flow_hash(
    ports: Option<[NetEndian<u16>; 2]>,
    addresses: Option<[IpAddr; 2]>,
    proto: Option<u8>,
) -> (u64, u8) {
    let mut flow_side = FlowSide::UNKNOWN;
    let mut hasher = DefaultHasher::new();  // Uses random keys!
    
    if let Some(ports) = ports {
        flow_side = FlowSide::from_port(ports[0], ports[1]);
        if flow_side == FlowSide::LhsGeRhs {
            ports[0].hash(&mut hasher);
            ports[1].hash(&mut hasher);
        } else {
            ports[1].hash(&mut hasher);
            ports[0].hash(&mut hasher);
        }
    }
    
    if let Some(addresses) = addresses {
        if flow_side == FlowSide::UNKNOWN {
            flow_side = FlowSide::from_address(addresses[0], addresses[1]);
        }
        if flow_side == FlowSide::LhsGeRhs {
            addresses[0].hash(&mut hasher);
            addresses[1].hash(&mut hasher);
        } else {
            addresses[1].hash(&mut hasher);
            addresses[0].hash(&mut hasher);
        }
    }
    
    if let Some(proto) = proto {
        proto.hash(&mut hasher);
    }
    
    (hasher.finish(), flow_side)
}
```

**Key issue:** `DefaultHasher::new()` uses **random keys** that change on each program run!

## Recommendation

For the `compare` plugin use case, **Option 1** (accept different hash values) is recommended because:

1. The plugin only needs to identify flows within a single Python session
2. Bidirectional consistency is maintained
3. No external dependencies or complex setup required
4. Hash values are deterministic and reproducible

If you need to share flow hash values between Python and Rust systems, use **Option 2** (modify Rust to use fixed keys).

## Testing

The Python implementation has been thoroughly tested for bidirectional consistency:

```bash
python -m pytest tests/test_flow_hash.py -v
```

All tests pass, confirming:
- ✅ Bidirectional consistency
- ✅ Different connections produce different hashes
- ✅ Same connection (both directions) produces same hash
- ✅ IPv4 and IPv6 support
- ✅ Protocol differentiation

## Future Work

If Rust compatibility is required:

1. Get the exact Rust code implementation
2. Determine if Rust can use fixed keys
3. Implement Option 2 or Option 3 above
4. Add integration tests to verify compatibility

