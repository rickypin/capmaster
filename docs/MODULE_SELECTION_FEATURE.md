# Module Selection Feature for Analyze Plugin

## Overview

The analyze plugin now supports selective module execution through the `--modules` / `-m` parameter. This allows users to run only specific analysis modules instead of all available modules.

## Usage

### Basic Syntax

```bash
# Run a single module
capmaster analyze -i <input> -m <module_name>

# Run multiple modules
capmaster analyze -i <input> -m <module1> -m <module2> -m <module3>

# Run all modules (default behavior)
capmaster analyze -i <input>
```

### Examples

#### 1. Analyze only protocol distribution

```bash
capmaster analyze -i capture.pcap -m protocol_hierarchy
```

**Output:**
- Only generates protocol hierarchy statistics
- Faster execution for quick protocol overview

#### 2. Analyze protocol distribution and DNS statistics

```bash
capmaster analyze -i capture.pcap -m protocol_hierarchy -m dns_stats
```

**Output:**
- Generates protocol hierarchy statistics
- Generates DNS statistics

#### 3. Analyze all available modules (default)

```bash
capmaster analyze -i capture.pcap
```

**Output:**
- Runs all 28 available analysis modules
- Generates comprehensive statistics

## Available Modules

The following modules are available for selection:

### Network Layer
- `protocol_hierarchy` - Protocol distribution and hierarchy
- `ipv4_conversations` - IPv4 conversation statistics
- `ipv4_destinations` - IPv4 destination statistics
- `ipv4_hosts` - IPv4 host statistics
- `ipv4_source_ttls` - IPv4 source TTL statistics

### Transport Layer
- `tcp_conversations` - TCP conversation statistics
- `tcp_completeness` - TCP connection completeness analysis
- `tcp_duration` - TCP connection duration statistics
- `tcp_zero_window` - TCP zero window detection
- `udp_conversations` - UDP conversation statistics

### Application Layer
- `dns_stats` - DNS statistics
- `dns_qr_stats` - DNS query/response statistics
- `http_stats` - HTTP statistics
- `http_response` - HTTP response code analysis
- `ftp_stats` - FTP statistics
- `ftp_data_stats` - FTP data transfer statistics
- `tls_alert` - TLS alert statistics
- `icmp_stats` - ICMP statistics
- `ssh_stats` - SSH statistics

### VoIP Protocols
- `sip_stats` - SIP statistics
- `rtp_stats` - RTP stream statistics
- `rtcp_stats` - RTCP statistics
- `mgcp_stats` - MGCP statistics
- `sdp_stats` - SDP statistics
- `voip_quality` - VoIP quality assessment

### Data Formats
- `json_stats` - JSON data statistics
- `xml_stats` - XML data statistics
- `mq_stats` - Message Queue statistics

## Error Handling

### Invalid Module Name

If you specify a module name that doesn't exist, the tool will:
1. Display an error message
2. List all available modules
3. Exit with non-zero status

**Example:**

```bash
$ capmaster analyze -i capture.pcap -m invalid_module

ERROR    Unknown module(s): invalid_module
ERROR    Available modules: dns_qr_stats, dns_stats, ftp_data_stats, ftp_stats, 
         http_response, http_stats, icmp_stats, ipv4_conversations, 
         ipv4_destinations, ipv4_hosts, ipv4_source_ttls, json_stats, 
         mgcp_stats, mq_stats, protocol_hierarchy, rtcp_stats, rtp_stats, 
         sdp_stats, sip_stats, ssh_stats, tcp_completeness, tcp_conversations, 
         tcp_duration, tcp_zero_window, tls_alert, udp_conversations, 
         voip_quality, xml_stats
```

## Implementation Details

### CLI Parameter

- **Short form:** `-m`
- **Long form:** `--modules`
- **Type:** Multiple (can be specified multiple times)
- **Default:** None (runs all modules)

### Module Filtering Logic

1. All modules are discovered and instantiated
2. If `--modules` is specified:
   - Validate all specified module names exist
   - Filter modules to only selected ones
   - Run only the filtered modules
3. If `--modules` is not specified:
   - Run all available modules (default behavior)

### Multiprocessing Support

The module selection feature works seamlessly with concurrent processing:

```bash
# Analyze multiple files with specific modules using 4 workers
capmaster analyze -i captures/ -m protocol_hierarchy -m dns_stats -w 4
```

## Testing

### Manual Testing Results

All tests passed successfully:

#### Test 1: Single Module Selection
```bash
$ capmaster analyze -i cases/V-001/VOIP.pcap -m protocol_hierarchy -o /tmp/test1
INFO     Running 1 selected module(s): protocol_hierarchy
INFO     Analysis complete. Total outputs: 1
✅ PASS - Only 1 file generated
```

#### Test 2: Multiple Module Selection
```bash
$ capmaster analyze -i cases/V-001/VOIP.pcap -m protocol_hierarchy -m sip_stats -o /tmp/test2
INFO     Running 2 selected module(s): protocol_hierarchy, sip_stats
INFO     Analysis complete. Total outputs: 2
✅ PASS - 2 files generated
```

#### Test 3: Invalid Module Name
```bash
$ capmaster analyze -i cases/V-001/VOIP.pcap -m invalid_module -o /tmp/test3
ERROR    Unknown module(s): invalid_module
ERROR    Available modules: [list of all modules]
✅ PASS - Error message displayed with available modules
```

#### Test 4: Default Behavior (No Module Selection)
```bash
$ capmaster analyze -i cases/V-001/VOIP.pcap -o /tmp/test4
INFO     Loaded 28 analysis modules
INFO     Analysis complete. Total outputs: 19
✅ PASS - All applicable modules executed
```

## Benefits

1. **Performance:** Run only needed modules for faster analysis
2. **Focused Analysis:** Get specific information without clutter
3. **Flexibility:** Combine any modules as needed
4. **User-Friendly:** Clear error messages and module listing
5. **Backward Compatible:** Default behavior unchanged

## Use Cases

### Quick Protocol Check
```bash
capmaster analyze -i suspicious.pcap -m protocol_hierarchy
```
Quickly identify what protocols are present in a capture.

### DNS Investigation
```bash
capmaster analyze -i traffic.pcap -m dns_stats -m dns_qr_stats
```
Focus on DNS-related analysis.

### VoIP Quality Analysis
```bash
capmaster analyze -i voip.pcap -m sip_stats -m rtp_stats -m voip_quality
```
Comprehensive VoIP quality assessment.

### TCP Performance Analysis
```bash
capmaster analyze -i performance.pcap -m tcp_conversations -m tcp_duration -m tcp_zero_window
```
Analyze TCP connection performance issues.

## Future Enhancements

Potential future improvements:
- Module groups (e.g., `--group voip` to run all VoIP modules)
- Module exclusion (e.g., `--exclude-module tcp_conversations`)
- Configuration file support for default module sets
- Module dependency resolution

