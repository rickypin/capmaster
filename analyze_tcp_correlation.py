#!/usr/bin/env python3
"""
Analyze TCP connection correlation between two pcap files
"""

import subprocess
import sys
from collections import defaultdict
from datetime import datetime

def extract_tcp_info(pcap_file):
    """Extract TCP connection information with timestamps"""
    cmd = [
        'tshark', '-r', pcap_file,
        '-T', 'fields',
        '-e', 'frame.number',
        '-e', 'frame.time_epoch',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'tcp.srcport',
        '-e', 'tcp.dstport',
        '-e', 'tcp.stream',
        '-e', 'tcp.flags.syn',
        '-e', 'tcp.flags.ack',
        '-e', 'tcp.len'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    packets = []
    for line in result.stdout.strip().split('\n'):
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) >= 10:
            packets.append({
                'frame': parts[0],
                'timestamp': float(parts[1]) if parts[1] else 0,
                'src_ip': parts[2],
                'dst_ip': parts[3],
                'src_port': parts[4],
                'dst_port': parts[5],
                'tcp_stream': parts[6],
                'syn': parts[7],
                'ack': parts[8],
                'len': parts[9]
            })
    
    return packets

def analyze_connections(packets):
    """Analyze TCP connections"""
    streams = defaultdict(list)
    for pkt in packets:
        streams[pkt['tcp_stream']].append(pkt)
    
    connections = []
    for stream_id, pkts in streams.items():
        if not pkts:
            continue
        
        # Find SYN packet
        syn_pkt = None
        for pkt in pkts:
            if pkt['syn'] == 'True' and pkt['ack'] == 'False':
                syn_pkt = pkt
                break
        
        if syn_pkt:
            connections.append({
                'stream_id': stream_id,
                'src_ip': syn_pkt['src_ip'],
                'dst_ip': syn_pkt['dst_ip'],
                'src_port': syn_pkt['src_port'],
                'dst_port': syn_pkt['dst_port'],
                'start_time': syn_pkt['timestamp'],
                'packet_count': len(pkts)
            })
    
    return connections

def main():
    pcap1 = '/Users/ricky/Downloads/2hops/dbs_1114/10.67.40.8_180115_180130_3.pcap'
    pcap2 = '/Users/ricky/Downloads/2hops/dbs_1114/10.89.87.183_1.pcap'
    
    print("=" * 80)
    print("TCP Connection Correlation Analysis")
    print("=" * 80)
    
    print(f"\n[1] Analyzing {pcap1}...")
    packets1 = extract_tcp_info(pcap1)
    connections1 = analyze_connections(packets1)
    print(f"    Total packets: {len(packets1)}")
    print(f"    TCP streams: {len(connections1)}")
    
    print(f"\n[2] Analyzing {pcap2}...")
    packets2 = extract_tcp_info(pcap2)
    connections2 = analyze_connections(packets2)
    print(f"    Total packets: {len(packets2)}")
    print(f"    TCP streams: {len(connections2)}")
    
    # Analyze IP addresses
    print(f"\n[3] IP Address Analysis:")
    print(f"\n  PCAP1 IP addresses:")
    ips1 = set()
    for conn in connections1:
        ips1.add(conn['src_ip'])
        ips1.add(conn['dst_ip'])
    for ip in sorted(ips1):
        print(f"    - {ip}")
    
    print(f"\n  PCAP2 IP addresses:")
    ips2 = set()
    for conn in connections2:
        ips2.add(conn['src_ip'])
        ips2.add(conn['dst_ip'])
    for ip in sorted(ips2):
        print(f"    - {ip}")
    
    common_ips = ips1 & ips2
    print(f"\n  Common IP addresses: {common_ips if common_ips else 'None'}")
    
    # Analyze port patterns
    print(f"\n[4] Port Analysis:")
    print(f"\n  PCAP1 connections (first 5):")
    for conn in connections1[:5]:
        print(f"    Stream {conn['stream_id']}: {conn['src_ip']}:{conn['src_port']} -> {conn['dst_ip']}:{conn['dst_port']} ({conn['packet_count']} packets)")
    
    print(f"\n  PCAP2 connections (first 5):")
    for conn in connections2[:5]:
        print(f"    Stream {conn['stream_id']}: {conn['src_ip']}:{conn['src_port']} -> {conn['dst_ip']}:{conn['dst_port']} ({conn['packet_count']} packets)")
    
    # Check for potential relay patterns
    print(f"\n[5] Potential Relay Pattern Analysis:")
    
    # Check if PCAP1 destination IPs appear as source in PCAP2
    pcap1_dst_ips = set(conn['dst_ip'] for conn in connections1)
    pcap2_src_ips = set(conn['src_ip'] for conn in connections2)
    
    potential_relay_ips = pcap1_dst_ips & pcap2_src_ips
    
    if potential_relay_ips:
        print(f"  Found potential relay IPs: {potential_relay_ips}")
        print(f"  This suggests a possible 2-hop connection pattern:")
        print(f"    Client -> Relay ({potential_relay_ips}) -> Server")
    else:
        print(f"  No obvious relay pattern detected")
        print(f"  PCAP1 destinations: {pcap1_dst_ips}")
        print(f"  PCAP2 sources: {pcap2_src_ips}")
    
    # Time correlation
    if connections1 and connections2:
        print(f"\n[6] Time Analysis:")
        pcap1_start = min(conn['start_time'] for conn in connections1)
        pcap1_end = max(conn['start_time'] for conn in connections1)
        pcap2_start = min(conn['start_time'] for conn in connections2)
        pcap2_end = max(conn['start_time'] for conn in connections2)
        
        print(f"  PCAP1 time range: {datetime.fromtimestamp(pcap1_start)} to {datetime.fromtimestamp(pcap1_end)}")
        print(f"  PCAP2 time range: {datetime.fromtimestamp(pcap2_start)} to {datetime.fromtimestamp(pcap2_end)}")
        
        # Check for time overlap
        if pcap1_start <= pcap2_end and pcap2_start <= pcap1_end:
            print(f"  ✓ Time ranges overlap - connections could be related")
        else:
            print(f"  ✗ Time ranges do not overlap")
    
    print("\n" + "=" * 80)

if __name__ == '__main__':
    main()

