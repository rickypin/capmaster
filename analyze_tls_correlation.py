#!/usr/bin/env python3
"""
Analyze TLS correlation between two pcap files based on Client Random numbers
"""

import subprocess
import sys
from collections import defaultdict

def extract_tls_client_hello(pcap_file):
    """Extract TLS Client Hello information from pcap file"""
    cmd = [
        'tshark', '-r', pcap_file,
        '-Y', 'tls.handshake.type == 1',
        '-T', 'fields',
        '-e', 'frame.number',
        '-e', 'frame.time_epoch',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'tcp.srcport',
        '-e', 'tcp.dstport',
        '-e', 'tcp.stream',
        '-e', 'tls.handshake.random'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    client_hellos = []
    for line in result.stdout.strip().split('\n'):
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) >= 8:
            client_hellos.append({
                'frame': parts[0],
                'timestamp': parts[1],
                'src_ip': parts[2],
                'dst_ip': parts[3],
                'src_port': parts[4],
                'dst_port': parts[5],
                'tcp_stream': parts[6],
                'random': parts[7]
            })
    
    return client_hellos

def extract_tcp_connections(pcap_file):
    """Extract TCP connection information"""
    cmd = [
        'tshark', '-r', pcap_file,
        '-Y', 'tcp.flags.syn == 1',
        '-T', 'fields',
        '-e', 'frame.number',
        '-e', 'frame.time_epoch',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'tcp.srcport',
        '-e', 'tcp.dstport',
        '-e', 'tcp.stream'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    connections = []
    for line in result.stdout.strip().split('\n'):
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) >= 7:
            connections.append({
                'frame': parts[0],
                'timestamp': parts[1],
                'src_ip': parts[2],
                'dst_ip': parts[3],
                'src_port': parts[4],
                'dst_port': parts[5],
                'tcp_stream': parts[6]
            })
    
    return connections

def main():
    pcap1 = '/Users/ricky/Downloads/2hops/dbs_1114/10.67.40.8_180115_180130_3.pcap'
    pcap2 = '/Users/ricky/Downloads/2hops/dbs_1114/10.89.87.183_1.pcap'
    
    print("=" * 80)
    print("TLS Correlation Analysis")
    print("=" * 80)
    
    print(f"\n[1] Extracting TLS Client Hello from {pcap1}...")
    client_hellos_1 = extract_tls_client_hello(pcap1)
    print(f"    Found {len(client_hellos_1)} Client Hello messages")
    
    print(f"\n[2] Extracting TLS Client Hello from {pcap2}...")
    client_hellos_2 = extract_tls_client_hello(pcap2)
    print(f"    Found {len(client_hellos_2)} Client Hello messages")
    
    # Build random number index
    random_to_pcap1 = {ch['random']: ch for ch in client_hellos_1 if ch['random']}
    random_to_pcap2 = {ch['random']: ch for ch in client_hellos_2 if ch['random']}
    
    # Find matching random numbers
    matching_randoms = set(random_to_pcap1.keys()) & set(random_to_pcap2.keys())
    
    print(f"\n[3] Correlation Results:")
    print(f"    Total unique Client Randoms in PCAP1: {len(random_to_pcap1)}")
    print(f"    Total unique Client Randoms in PCAP2: {len(random_to_pcap2)}")
    print(f"    Matching Client Randoms: {len(matching_randoms)}")
    
    if matching_randoms:
        print(f"\n[4] Matched TLS Sessions (showing first 10):")
        print("-" * 80)
        for i, random in enumerate(list(matching_randoms)[:10], 1):
            ch1 = random_to_pcap1[random]
            ch2 = random_to_pcap2[random]
            print(f"\nMatch #{i}:")
            print(f"  Client Random: {random}")
            print(f"  PCAP1 (Frame {ch1['frame']}): {ch1['src_ip']}:{ch1['src_port']} -> {ch1['dst_ip']}:{ch1['dst_port']} (TCP Stream {ch1['tcp_stream']})")
            print(f"  PCAP2 (Frame {ch2['frame']}): {ch2['src_ip']}:{ch2['src_port']} -> {ch2['dst_ip']}:{ch2['dst_port']} (TCP Stream {ch2['tcp_stream']})")
    else:
        print("\n[!] No matching TLS Client Random numbers found!")
        print("\nShowing sample Client Randoms from each file:")
        print("\nPCAP1 samples:")
        for ch in client_hellos_1[:3]:
            print(f"  {ch['random']} - {ch['src_ip']}:{ch['src_port']} -> {ch['dst_ip']}:{ch['dst_port']}")
        print("\nPCAP2 samples:")
        for ch in client_hellos_2[:3]:
            print(f"  {ch['random']} - {ch['src_ip']}:{ch['src_port']} -> {ch['dst_ip']}:{ch['dst_port']}")
    
    print("\n" + "=" * 80)

if __name__ == '__main__':
    main()

