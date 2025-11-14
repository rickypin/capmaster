#!/usr/bin/env python3
"""Test script to verify ack_lost_segment metric is properly extracted."""

from capmaster.plugins.match.quality_analyzer import QualityMetrics

def test_quality_metrics():
    """Test QualityMetrics with new ack_lost_segment fields."""
    
    # Create a metrics instance with sample data
    metrics = QualityMetrics(
        server_ip="10.93.75.130",
        server_port=8443,
        client_total_packets=1000,
        client_retransmissions=10,
        client_duplicate_acks=5,
        client_lost_segments=8,  # Total lost segments detected
        client_ack_lost_segments=5,  # ACKed segments (capture miss)
        server_total_packets=1000,
        server_retransmissions=8,
        server_duplicate_acks=4,
        server_lost_segments=6,
        server_ack_lost_segments=4,
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
    print(f"  ACK Lost Segments:       {metrics.client_ack_lost_segments:,} ({metrics.client_ack_lost_rate:.2f}%)")
    print(f"  Real Loss (calculated):  {metrics.client_lost_segments - metrics.client_ack_lost_segments:,} ({metrics.client_real_loss_rate:.2f}%)")
    
    print("\nServer -> Client:")
    print(f"  Total Packets:           {metrics.server_total_packets:,}")
    print(f"  Retransmissions:         {metrics.server_retransmissions:,} ({metrics.server_retransmission_rate:.2f}%)")
    print(f"  Duplicate ACKs:          {metrics.server_duplicate_acks:,} ({metrics.server_duplicate_ack_rate:.2f}%)")
    print(f"  Lost Segments:           {metrics.server_lost_segments:,} ({metrics.server_loss_rate:.2f}%)")
    print(f"  ACK Lost Segments:       {metrics.server_ack_lost_segments:,} ({metrics.server_ack_lost_rate:.2f}%)")
    print(f"  Real Loss (calculated):  {metrics.server_lost_segments - metrics.server_ack_lost_segments:,} ({metrics.server_real_loss_rate:.2f}%)")
    
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
    
    # Verify calculations
    assert metrics.client_real_loss_rate == ((metrics.client_lost_segments - metrics.client_ack_lost_segments) / metrics.client_total_packets) * 100
    assert metrics.server_real_loss_rate == ((metrics.server_lost_segments - metrics.server_ack_lost_segments) / metrics.server_total_packets) * 100
    
    print("✅ All assertions passed!")
    print("=" * 80)

if __name__ == "__main__":
    test_quality_metrics()

