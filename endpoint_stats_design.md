# Endpoint Statistics Feature Design

## Requirements

Add a new parameter to the match plugin while keeping current matching parameters and algorithms unchanged:

1. **Count only matched connections**: Process only connections successfully matched between PCAP files A and B
2. **Remove client port**: Aggregate by `(Client IP, Server IP, Server Port)` tuple
3. **Accurate server detection**: Improve current server detection logic for better precision
4. **Paired output format**: Display endpoint tuples from both PCAP files A and B as pairs with their connection counts

## Current Server Detection Issues

### Current Logic
```python
if syn_packet:
    # Has SYN packet: SYN destination = server
    server_ip = syn_packet.dst_ip
    server_port = syn_packet.dst_port
else:
    # No SYN packet: first packet destination = server
    server_ip = first_packet.dst_ip
    server_port = first_packet.dst_port
```

### Problems

1. **Inaccurate without SYN**: In mid-stream captures, first packet may be server response
2. **No bidirectional handling**: Cannot handle bidirectional traffic at capture point
3. **Missing port heuristics**: Doesn't leverage well-known port information

## Improved Multi-Layer Server Detection

### Detection Priority (High to Low)

```
Priority 1: SYN packet direction (Most reliable)
  ↓ Failed
Priority 2: Port number heuristics (Well-known ports)
  ↓ Failed
Priority 3: Traffic pattern analysis (Packet/byte statistics)
  ↓ Failed
Priority 4: Port number comparison (Fallback)
```

### Detection Rules

#### Priority 1: SYN Packet Direction
```python
if syn_packet:
    # SYN destination = server (most reliable)
    server_ip = syn_packet.dst_ip
    server_port = syn_packet.dst_port
    confidence = "HIGH"
```

#### Priority 2: Port Number Heuristics
```python
# Well-known ports (IANA registered 0-1023)
WELL_KNOWN_PORTS = {
    20, 21,      # FTP
    22,          # SSH
    23,          # Telnet
    25,          # SMTP
    53,          # DNS
    80,          # HTTP
    110,         # POP3
    143,         # IMAP
    443,         # HTTPS
    3306,        # MySQL
    5432,        # PostgreSQL
    6379,        # Redis
    27017,       # MongoDB
}

# Database ports (extended list)
DATABASE_PORTS = {
    1433,        # MS SQL Server
    1521,        # Oracle
    3306,        # MySQL
    5432,        # PostgreSQL
    6379,        # Redis
    7000, 7001,  # Cassandra
    8529,        # ArangoDB
    9042,        # Cassandra CQL
    27017,       # MongoDB
    50000,       # DB2
}

def determine_server_by_port(port1, port2):
    # Case 1: One is well-known, other is not
    if port1 in WELL_KNOWN_PORTS and port2 not in WELL_KNOWN_PORTS:
        return port1, "HIGH"
    if port2 in WELL_KNOWN_PORTS and port1 not in WELL_KNOWN_PORTS:
        return port2, "HIGH"
    
    # Case 2: One is database port, other is not
    if port1 in DATABASE_PORTS and port2 not in DATABASE_PORTS:
        return port1, "MEDIUM"
    if port2 in DATABASE_PORTS and port1 not in DATABASE_PORTS:
        return port2, "MEDIUM"
    
    # Case 3: One < 1024 (system port), other >= 1024
    if port1 < 1024 and port2 >= 1024:
        return port1, "MEDIUM"
    if port2 < 1024 and port1 >= 1024:
        return port2, "MEDIUM"
    
    return None, "UNKNOWN"
```

#### Priority 3: Traffic Pattern Analysis
```python
def determine_server_by_traffic(packets, ip1, ip2):
    """
    Determine server by traffic pattern
    Assumption: Server typically sends more data (responses)
    """
    # Count bytes in each direction
    bytes_from_ip1 = sum(p.length for p in packets if p.src_ip == ip1)
    bytes_from_ip2 = sum(p.length for p in packets if p.src_ip == ip2)
    
    # Count packets in each direction
    packets_from_ip1 = sum(1 for p in packets if p.src_ip == ip1)
    packets_from_ip2 = sum(1 for p in packets if p.src_ip == ip2)
    
    # If one side sends significantly more data (2x+), it's likely the server
    if bytes_from_ip1 > bytes_from_ip2 * 2:
        return ip1, "LOW"
    if bytes_from_ip2 > bytes_from_ip1 * 2:
        return ip2, "LOW"
    
    # If one side sends more packets (1.5x+), it's likely the server
    if packets_from_ip1 > packets_from_ip2 * 1.5:
        return ip1, "LOW"
    if packets_from_ip2 > packets_from_ip1 * 1.5:
        return ip2, "LOW"
    
    return None, "UNKNOWN"
```

## New Parameter Design

### CLI Parameter

```bash
python -m capmaster match \
  -i file1.pcap,file2.pcap \
  --endpoint-stats  # New parameter: generate endpoint statistics
```

With optional output file:

```bash
python -m capmaster match \
  -i file1.pcap,file2.pcap \
  --endpoint-stats \
  --endpoint-stats-output stats.txt
```

### Parameter Definition

```python
@click.option(
    "--endpoint-stats",
    is_flag=True,
    default=False,
    help="Generate endpoint statistics (client IP, server IP, server port) for matched connections"
)
@click.option(
    "--endpoint-stats-output",
    type=click.Path(path_type=Path),
    help="Output file for endpoint statistics (default: stdout)"
)
```

## Implementation Design

### 1. Data Structures

```python
@dataclass
class ServerInfo:
    """Server detection information"""
    server_ip: str
    server_port: int
    client_ip: str
    client_port: int
    confidence: str  # HIGH, MEDIUM, LOW, VERY_LOW, UNKNOWN
    method: str      # SYN_PACKET, PORT_HEURISTIC, TRAFFIC_PATTERN, FALLBACK

@dataclass
class EndpointTuple:
    """Endpoint tuple (client IP, server IP, server port)"""
    client_ip: str
    server_ip: str
    server_port: int
    
    def __hash__(self):
        return hash((self.client_ip, self.server_ip, self.server_port))
    
    def __eq__(self, other):
        return (self.client_ip == other.client_ip and 
                self.server_ip == other.server_ip and 
                self.server_port == other.server_port)

@dataclass
class EndpointPairStats:
    """Paired endpoint statistics for files A and B"""
    tuple_a: EndpointTuple  # Endpoint tuple from file A
    tuple_b: EndpointTuple  # Endpoint tuple from file B
    count: int              # Number of matched connections
    confidence: str         # Average confidence level
```

### 2. New Modules

**File**: `capmaster/plugins/match/server_detector.py`

```python
"""Server detection module with multi-layer heuristics"""

class ServerDetector:
    """Multi-layer server detector"""
    
    WELL_KNOWN_PORTS = {...}
    DATABASE_PORTS = {...}
    
    def detect(self, connection: TcpConnection) -> ServerInfo:
        """Detect server using multi-layer approach"""
        # Priority 1: SYN packet
        if connection.syn_options:
            return self._detect_by_syn(connection)
        
        # Priority 2: Port heuristics
        info = self._detect_by_port(connection)
        if info.confidence in ["HIGH", "MEDIUM"]:
            return info
        
        # Priority 3: Traffic pattern
        info = self._detect_by_traffic(connection)
        if info.confidence == "LOW":
            return info
        
        # Priority 4: Fallback
        return self._detect_fallback(connection)
```

**File**: `capmaster/plugins/match/endpoint_stats.py`

```python
"""Endpoint statistics collector"""

class EndpointStatsCollector:
    """Collect and aggregate endpoint statistics for matched connections"""
    
    def __init__(self, detector: ServerDetector):
        self.detector = detector
        # Key: (tuple_a, tuple_b), Value: count
        self.pair_stats: dict[tuple[EndpointTuple, EndpointTuple], int] = {}
        self.confidences: dict[tuple[EndpointTuple, EndpointTuple], list[str]] = {}
    
    def add_match(self, match: ConnectionMatch):
        """Add a matched connection pair"""
        # Detect server for both connections
        info_a = self.detector.detect(match.conn1)
        info_b = self.detector.detect(match.conn2)
        
        # Create endpoint tuples
        tuple_a = EndpointTuple(
            client_ip=info_a.client_ip,
            server_ip=info_a.server_ip,
            server_port=info_a.server_port
        )
        tuple_b = EndpointTuple(
            client_ip=info_b.client_ip,
            server_ip=info_b.server_ip,
            server_port=info_b.server_port
        )
        
        # Use ordered pair as key (tuple_a, tuple_b)
        pair_key = (tuple_a, tuple_b)
        
        # Increment count
        self.pair_stats[pair_key] = self.pair_stats.get(pair_key, 0) + 1
        
        # Track confidences
        if pair_key not in self.confidences:
            self.confidences[pair_key] = []
        self.confidences[pair_key].append(info_a.confidence)
    
    def get_stats(self) -> list[EndpointPairStats]:
        """Get aggregated statistics"""
        results = []
        for (tuple_a, tuple_b), count in self.pair_stats.items():
            # Calculate average confidence
            confs = self.confidences[(tuple_a, tuple_b)]
            avg_conf = self._average_confidence(confs)
            
            results.append(EndpointPairStats(
                tuple_a=tuple_a,
                tuple_b=tuple_b,
                count=count,
                confidence=avg_conf
            ))
        
        # Sort by count (descending)
        results.sort(key=lambda x: x.count, reverse=True)
        return results
    
    def _average_confidence(self, confidences: list[str]) -> str:
        """Calculate average confidence level"""
        conf_map = {"HIGH": 4, "MEDIUM": 3, "LOW": 2, "VERY_LOW": 1, "UNKNOWN": 0}
        avg = sum(conf_map.get(c, 0) for c in confidences) / len(confidences)
        
        if avg >= 3.5:
            return "HIGH"
        elif avg >= 2.5:
            return "MEDIUM"
        elif avg >= 1.5:
            return "LOW"
        else:
            return "VERY_LOW"
```

### 3. Output Format

```
================================================================================
Endpoint Statistics (Matched Connections Only)
================================================================================

File A: 0215-0315_10.64.0.125.pcap
File B: idc_appdbdefault_20250910030547.pcap

Total unique endpoint pairs: 3
Total matched connections: 3

Endpoint Pairs:
--------------------------------------------------------------------------------

[1] Count: 1 | Confidence: HIGH
    File A: Client 10.38.92.45 → Server 10.64.0.125:26303
    File B: Client 10.38.92.45 → Server 10.64.0.125:26303

[2] Count: 1 | Confidence: HIGH
    File A: Client 10.38.92.45 → Server 10.64.0.125:26302
    File B: Client 10.38.92.45 → Server 10.64.0.125:26302

[3] Count: 1 | Confidence: HIGH
    File A: Client 10.38.92.44 → Server 10.64.0.125:26301
    File B: Client 10.38.92.44 → Server 10.64.0.125:26301

================================================================================
```

Alternative compact format:

```
================================================================================
Endpoint Statistics Summary
================================================================================

File A: 0215-0315_10.64.0.125.pcap
File B: idc_appdbdefault_20250910030547.pcap

Client IP (A)  | Server IP (A)  | Port (A) | Client IP (B)  | Server IP (B)  | Port (B) | Count | Conf
---------------|----------------|----------|----------------|----------------|----------|-------|------
10.38.92.45    | 10.64.0.125    | 26303    | 10.38.92.45    | 10.64.0.125    | 26303    | 1     | HIGH
10.38.92.45    | 10.64.0.125    | 26302    | 10.38.92.45    | 10.64.0.125    | 26302    | 1     | HIGH
10.38.92.44    | 10.64.0.125    | 26301    | 10.38.92.44    | 10.64.0.125    | 26301    | 1     | HIGH

================================================================================
```

## Test Cases

### Test Case 1: dbs_ori files
```bash
python -m capmaster match \
  -i /Users/ricky/Downloads/dbs_ori/0215-0315_10.64.0.125.pcap,/Users/ricky/Downloads/dbs_ori/idc_appdbdefault_20250910030547.pcap \
  --endpoint-stats
```

Expected: 3 endpoint pairs with HIGH confidence (SYN packets available)

### Test Case 2: TC-001-1-20160407 files
```bash
python -m capmaster match \
  -i cases/TC-001-1-20160407/TC-001-1-20160407-A.pcap,cases/TC-001-1-20160407/TC-001-1-20160407-B.pcap \
  --endpoint-stats
```

Expected: Endpoint pairs with varying confidence levels based on available information

## Implementation Steps

1. **Phase 1**: Implement `ServerDetector` class
   - SYN packet detection
   - Port heuristics
   - Traffic pattern analysis
   - Unit tests

2. **Phase 2**: Implement `EndpointStatsCollector` class
   - Paired statistics collection
   - Aggregation logic
   - Unit tests

3. **Phase 3**: Integrate into `MatchPlugin`
   - Add CLI parameters
   - Integrate statistics collection
   - Format output
   - Integration tests

4. **Phase 4**: Optimization and documentation
   - Performance tuning
   - User documentation
   - Examples

## Summary

This design solves the requirements through:

1. **Paired output**: Endpoint tuples from files A and B are displayed as pairs
2. **Multi-layer detection**: SYN → Port heuristics → Traffic pattern → Fallback
3. **Confidence tracking**: Each detection has a confidence level
4. **Backward compatible**: New optional parameter, doesn't affect existing functionality
5. **Clear output**: Paired format shows relationship between files A and B

Key advantages:
- ✅ Accurate server detection (well-known ports + traffic patterns)
- ✅ Keeps existing matching algorithm unchanged
- ✅ Only counts matched connections
- ✅ Aggregates by (client IP, server IP, server port) tuple
- ✅ Paired output format shows A-B relationship clearly
- ✅ Easy to analyze and understand

