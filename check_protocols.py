#!/usr/bin/env python3
"""Check protocol hierarchy in all cases_02 directories."""

import subprocess
import re
from pathlib import Path
from collections import defaultdict

def get_protocol_hierarchy(pcap_file: Path) -> set[str]:
    """Get protocol hierarchy from a pcap file using tshark."""
    try:
        result = subprocess.run(
            ["tshark", "-r", str(pcap_file), "-q", "-z", "io,phs"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        
        if result.returncode != 0:
            print(f"Error processing {pcap_file}: {result.stderr}")
            return set()
        
        # Parse protocols from output
        protocols = set()
        pattern = re.compile(r"^\s*([a-zA-Z0-9_\-\.]+)\s+frames:", re.MULTILINE)
        
        for match in pattern.finditer(result.stdout):
            protocol = match.group(1).lower()
            protocols.add(protocol)
        
        return protocols
    except Exception as e:
        print(f"Exception processing {pcap_file}: {e}")
        return set()

def main():
    """Main function."""
    cases_dir = Path("cases_02")
    
    if not cases_dir.exists():
        print(f"Directory {cases_dir} does not exist")
        return
    
    # Collect all protocols from all pcap files
    all_protocols = set()
    case_protocols = defaultdict(set)
    
    # Find all pcap files
    pcap_files = list(cases_dir.rglob("*.pcap")) + list(cases_dir.rglob("*.pcapng"))
    
    print(f"Found {len(pcap_files)} pcap files")
    print("=" * 80)
    
    for pcap_file in sorted(pcap_files):
        print(f"\nProcessing: {pcap_file.relative_to(cases_dir)}")
        protocols = get_protocol_hierarchy(pcap_file)
        
        if protocols:
            print(f"  Protocols: {', '.join(sorted(protocols))}")
            all_protocols.update(protocols)
            case_name = pcap_file.parent.name
            case_protocols[case_name].update(protocols)
        else:
            print(f"  No protocols detected")
    
    print("\n" + "=" * 80)
    print("\nALL UNIQUE PROTOCOLS FOUND:")
    print("=" * 80)
    for protocol in sorted(all_protocols):
        print(f"  - {protocol}")
    
    print(f"\nTotal unique protocols: {len(all_protocols)}")
    
    # Check against current analyze modules
    print("\n" + "=" * 80)
    print("CHECKING AGAINST CURRENT ANALYZE MODULES:")
    print("=" * 80)
    
    # Current modules and their required protocols
    module_protocols = {
        "protocol_hierarchy": set(),  # Always runs
        "ipv4_conversations": {"ip"},
        "ipv4_source_ttls": {"ip"},
        "ipv4_destinations": {"ip"},
        "ipv4_hosts": {"ip"},
        "tcp_conversations": {"tcp"},
        "tcp_completeness": {"tcp"},
        "tcp_duration": {"tcp"},
        "tcp_zero_window": {"tcp"},
        "udp_conversations": {"udp"},
        "http_stats": {"http"},
        "http_response": {"http"},
        "dns_stats": {"dns"},
        "dns_qr_stats": {"dns"},
        "ftp_stats": {"ftp"},
        "icmp_stats": {"icmp"},
        "tls_alert": {"tls"},
    }
    
    # Protocols covered by modules
    covered_protocols = set()
    for protocols in module_protocols.values():
        covered_protocols.update(protocols)
    
    # Find uncovered protocols
    uncovered = all_protocols - covered_protocols
    
    print("\nProtocols COVERED by current modules:")
    for protocol in sorted(covered_protocols):
        if protocol in all_protocols:
            print(f"  ✓ {protocol}")
    
    print("\nProtocols NOT COVERED by current modules:")
    if uncovered:
        for protocol in sorted(uncovered):
            # Count how many cases have this protocol
            count = sum(1 for protocols in case_protocols.values() if protocol in protocols)
            print(f"  ✗ {protocol} (found in {count} cases)")
    else:
        print("  (All protocols are covered)")
    
    # Show protocol distribution by case
    print("\n" + "=" * 80)
    print("PROTOCOL DISTRIBUTION BY CASE:")
    print("=" * 80)
    
    for case_name in sorted(case_protocols.keys()):
        protocols = case_protocols[case_name]
        print(f"\n{case_name}:")
        print(f"  Protocols: {', '.join(sorted(protocols))}")

if __name__ == "__main__":
    main()

