#!/usr/bin/env python3
"""Test script to verify ServerDetector behavior with service list."""

from pathlib import Path
from capmaster.plugins.match.server_detector import ServerDetector
from capmaster.core.connection.models import TcpConnection

# Create a test connection
def create_test_connection():
    return TcpConnection(
        stream_id=0,
        protocol=6,
        client_ip="10.38.92.44",
        client_port=35100,
        server_ip="10.64.0.125",
        server_port=26301,
        syn_timestamp=0.0,
        syn_options="",
        client_isn=0,
        server_isn=0,
        tcp_timestamp_tsval="",
        tcp_timestamp_tsecr="",
        client_payload_md5="",
        server_payload_md5="",
        length_signature="",
        is_header_only=False,
        ipid_first=0,
        ipid_set=set(),
        client_ipid_set=set(),
        server_ipid_set=set(),
        first_packet_time=0.0,
        last_packet_time=0.0,
        packet_count=1,
        client_ttl=0,
        server_ttl=0,
        total_bytes=0,
        has_syn=False,
    )

# Test without service list
print("=" * 80)
print("Test 1: Without service list")
print("=" * 80)
detector1 = ServerDetector(service_list_path=None)
conn = create_test_connection()
result1 = detector1.detect(conn)
print(f"Connection: {conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port}")
print(f"Detected server: {result1.server_ip}:{result1.server_port}")
print(f"Detected client: {result1.client_ip}:{result1.client_port}")
print(f"Confidence: {result1.confidence}")
print(f"Method: {result1.method}")
print()

# Test with service list
print("=" * 80)
print("Test 2: With service list (services.txt)")
print("=" * 80)
service_list_path = Path("services.txt")
if service_list_path.exists():
    print(f"Service list content:")
    print(service_list_path.read_text())
    print()
    
    detector2 = ServerDetector(service_list_path=service_list_path)
    print(f"Loaded service list IPs: {detector2._service_list_ips}")
    print(f"Loaded service list endpoints: {detector2._service_list_endpoints}")
    print()
    
    conn = create_test_connection()
    result2 = detector2.detect(conn)
    print(f"Connection: {conn.client_ip}:{conn.client_port} <-> {conn.server_ip}:{conn.server_port}")
    print(f"Detected server: {result2.server_ip}:{result2.server_port}")
    print(f"Detected client: {result2.client_ip}:{result2.client_port}")
    print(f"Confidence: {result2.confidence}")
    print(f"Method: {result2.method}")
    print()
    
    # Check matching logic
    print("Matching logic:")
    server_matched = (
        (conn.server_ip, conn.server_port) in detector2._service_list_endpoints
        or conn.server_ip in detector2._service_list_ips
    )
    client_matched = (
        (conn.client_ip, conn.client_port) in detector2._service_list_endpoints
        or conn.client_ip in detector2._service_list_ips
    )
    print(f"  server_matched: {server_matched}")
    print(f"  client_matched: {client_matched}")
else:
    print("services.txt not found!")

