#!/usr/bin/env python3
"""Test script to verify ack_lost_segment metric is properly extracted.

NOTE:
- This is a manual verification script referenced from docs/ACK_LOST_SEGMENT_FEATURE.md.
- It is not collected by pytest; run it manually from the project root with `python scripts/manual/test_ack_lost_segment.py` when needed.
"""

from capmaster.plugins.match.quality_analyzer import QualityMetrics

def test_quality_metrics():
    """Test QualityMetrics with new ack_lost_segment fields."""
    
    # Create a metrics instance with sample data
    # Simulating the case from user's example:
    # File A: C->S Lost=0, C->S ACK Lost=3, S->C Lost=3, S->C ACK Lost=0
    metrics = QualityMetrics(
        server_ip="10.64.0.125",
        server_port=26301,
        client_total_packets=370,
        client_retransmissions=0,
        client_duplicate_acks=0,
        client_lost_segments=0,  # C->S lost segments
        client_ack_lost_segments=3,  # C->S ACK packets that ACKed S->C segments not captured
        server_total_packets=374,
        server_retransmissions=5,
        server_duplicate_acks=1,
        server_lost_segments=3,  # S->C lost segments
        server_ack_lost_segments=0,  # S->C ACK packets that ACKed C->S segments not captured
    )
    
    print("=" * 80)
    print("Quality Metrics Test")
    print("=" * 80)
    print(f"\nServer: {metrics.server_ip}:{metrics.server_port}")
    print("\nClient -> Server:")
    print(f"  Total Packets:           {metrics.client_total_packets:,}")
    print(f"  Retransmissions:         {metrics.client_retransmissions:,} ({metrics.client_retransmission_rate:.2f}%)")
    print(f"  Duplicate ACKs:          {metrics.client_duplicate_acks:,} ({metrics.client_duplicate_ack_rate:.2f}%)")
    print(f"  Lost Segments:           {metrics.client_lost_segments:,} ({metrics.client_loss_rate:.2f}%)")
    print(f"  ACK Lost Segments:       {metrics.client_ack_lost_segments:,} ({metrics.client_ack_lost_rate:.2f}%) [C->S ACKs that ACKed S->C uncaptured segments]")
    client_real_loss = max(0, metrics.client_lost_segments - metrics.server_ack_lost_segments)
    print(f"  Real Loss (calculated):  {client_real_loss:,} ({metrics.client_real_loss_rate:.2f}%) [C->S lost - S->C ack_lost]")

    print("\nServer -> Client:")
    print(f"  Total Packets:           {metrics.server_total_packets:,}")
    print(f"  Retransmissions:         {metrics.server_retransmissions:,} ({metrics.server_retransmission_rate:.2f}%)")
    print(f"  Duplicate ACKs:          {metrics.server_duplicate_acks:,} ({metrics.server_duplicate_ack_rate:.2f}%)")
    print(f"  Lost Segments:           {metrics.server_lost_segments:,} ({metrics.server_loss_rate:.2f}%)")
    print(f"  ACK Lost Segments:       {metrics.server_ack_lost_segments:,} ({metrics.server_ack_lost_rate:.2f}%) [S->C ACKs that ACKed C->S uncaptured segments]")
    server_real_loss = max(0, metrics.server_lost_segments - metrics.client_ack_lost_segments)
    print(f"  Real Loss (calculated):  {server_real_loss:,} ({metrics.server_real_loss_rate:.2f}%) [S->C lost - C->S ack_lost]")
    
    print("\n" + "=" * 80)
    print("Analysis:")
    print("=" * 80)
    
    # Client -> Server analysis
    if metrics.client_ack_lost_segments > 0:
        capture_miss_ratio = (metrics.client_ack_lost_segments / metrics.client_lost_segments * 100) if metrics.client_lost_segments > 0 else 0
        print(f"\nClient -> Server:")
        print(f"  Lost Segments: {metrics.client_lost_segments}")
        print(f"  ACK Lost Segments: {metrics.client_ack_lost_segments} ({capture_miss_ratio:.1f}% of lost segments)")
        print(f"  Real Network Loss: {metrics.client_lost_segments - metrics.client_ack_lost_segments}")
        if capture_miss_ratio > 50:
            print(f"  ⚠️  High capture miss rate - most 'lost' segments were actually captured at peer")
        else:
            print(f"  ⚠️  Significant real packet loss detected")
    
    # Server -> Client analysis
    if metrics.server_ack_lost_segments > 0:
        capture_miss_ratio = (metrics.server_ack_lost_segments / metrics.server_lost_segments * 100) if metrics.server_lost_segments > 0 else 0
        print(f"\nServer -> Client:")
        print(f"  Lost Segments: {metrics.server_lost_segments}")
        print(f"  ACK Lost Segments: {metrics.server_ack_lost_segments} ({capture_miss_ratio:.1f}% of lost segments)")
        print(f"  Real Network Loss: {metrics.server_lost_segments - metrics.server_ack_lost_segments}")
        if capture_miss_ratio > 50:
            print(f"  ⚠️  High capture miss rate - most 'lost' segments were actually captured at peer")
        else:
            print(f"  ⚠️  Significant real packet loss detected")
    
    print("\n" + "=" * 80)
    
    # Verify calculations (cross-direction)
    expected_client_real_loss_rate = (max(0, metrics.client_lost_segments - metrics.server_ack_lost_segments) / metrics.client_total_packets) * 100
    expected_server_real_loss_rate = (max(0, metrics.server_lost_segments - metrics.client_ack_lost_segments) / metrics.server_total_packets) * 100

    assert abs(metrics.client_real_loss_rate - expected_client_real_loss_rate) < 0.01, f"Client real loss rate mismatch: {metrics.client_real_loss_rate} != {expected_client_real_loss_rate}"
    assert abs(metrics.server_real_loss_rate - expected_server_real_loss_rate) < 0.01, f"Server real loss rate mismatch: {metrics.server_real_loss_rate} != {expected_server_real_loss_rate}"
    
    print("✅ All assertions passed!")
    print("=" * 80)

if __name__ == "__main__":
    test_quality_metrics()

