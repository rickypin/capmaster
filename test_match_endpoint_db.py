#!/usr/bin/env python3
"""Test script for match plugin endpoint statistics database writer."""

import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from capmaster.plugins.match.db_writer import MatchDatabaseWriter
from capmaster.plugins.match.endpoint_stats import EndpointTuple, EndpointPairStats

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def test_endpoint_stats_write():
    """Test writing endpoint statistics to database."""
    
    # Database connection parameters
    db_connection = "postgresql://postgres:password@172.16.200.156:5433/r2"
    kase_id = 137
    
    logger.info("=" * 80)
    logger.info("Testing Endpoint Statistics Database Writer")
    logger.info("=" * 80)
    
    try:
        # Create test endpoint statistics with network hops
        endpoint_stats = [
            # Scenario 1: Both client and server have intermediate devices
            EndpointPairStats(
                tuple_a=EndpointTuple(
                    client_ip="192.168.1.100",
                    server_ip="10.0.0.50",
                    server_port=80,
                    protocol=6,  # TCP
                ),
                tuple_b=EndpointTuple(
                    client_ip="172.16.0.200",
                    server_ip="10.0.0.51",
                    server_port=80,
                    protocol=6,  # TCP
                ),
                count=5,
                confidence="HIGH",
                client_ttl_a=64,
                server_ttl_a=60,
                client_ttl_b=128,
                server_ttl_b=120,
                client_hops_a=0,   # Direct connection
                server_hops_a=4,   # 4 hops to server
                client_hops_b=0,   # Direct connection
                server_hops_b=8,   # 8 hops to server
            ),
            # Scenario 2: Only server has intermediate devices
            EndpointPairStats(
                tuple_a=EndpointTuple(
                    client_ip="192.168.1.101",
                    server_ip="10.0.0.52",
                    server_port=443,
                    protocol=6,  # TCP
                ),
                tuple_b=EndpointTuple(
                    client_ip="172.16.0.201",
                    server_ip="10.0.0.53",
                    server_port=443,
                    protocol=6,  # TCP
                ),
                count=3,
                confidence="MEDIUM",
                client_ttl_a=128,
                server_ttl_a=118,
                client_ttl_b=64,
                server_ttl_b=62,
                client_hops_a=0,   # Direct connection
                server_hops_a=10,  # 10 hops to server
                client_hops_b=0,   # Direct connection
                server_hops_b=2,   # 2 hops to server
            ),
            # Scenario 3: Both client and server have intermediate devices
            EndpointPairStats(
                tuple_a=EndpointTuple(
                    client_ip="192.168.1.102",
                    server_ip="10.0.0.54",
                    server_port=22,
                    protocol=6,  # TCP
                ),
                tuple_b=EndpointTuple(
                    client_ip="172.16.0.202",
                    server_ip="10.0.0.55",
                    server_port=22,
                    protocol=6,  # TCP
                ),
                count=2,
                confidence="HIGH",
                client_ttl_a=61,
                server_ttl_a=58,
                client_ttl_b=125,
                server_ttl_b=115,
                client_hops_a=3,   # 3 hops from client
                server_hops_a=6,   # 6 hops to server
                client_hops_b=3,   # 3 hops from client
                server_hops_b=13,  # 13 hops to server
            ),
        ]
        
        # PCAP ID mapping
        pcap_id_mapping = {
            "A_processed.pcap": 0,
            "B_processed.pcap": 1,
        }
        
        # Create database writer
        with MatchDatabaseWriter(db_connection, kase_id) as db:
            logger.info(f"Connected to database for kase_id={kase_id}")
            
            # Ensure table exists
            db.ensure_table_exists()
            
            # Write endpoint statistics
            logger.info("\nWriting endpoint statistics...")
            records_inserted = db.write_endpoint_stats(
                endpoint_stats=endpoint_stats,
                pcap_id_mapping=pcap_id_mapping,
                file1_path="A_processed.pcap",
                file2_path="B_processed.pcap",
            )
            
            # Commit
            db.commit()
            
            logger.info("\n" + "=" * 80)
            logger.info(f"✓ Successfully wrote {records_inserted} records to database")
            logger.info("=" * 80)
            
            # Verify the records were inserted
            logger.info("\nVerifying inserted records...")
            db._cursor.execute(f"""
                SELECT id, pcap_id, group_id, ip, port, proto, type, display_name
                FROM {db.full_table_name}
                WHERE group_id IN (1, 2, 3)
                ORDER BY group_id, pcap_id, type;
            """)
            
            records = db._cursor.fetchall()
            logger.info(f"\nFound {len(records)} records with group_id IN (1, 2, 3):")
            logger.info("-" * 80)

            current_group = None
            for record in records:
                id_, pcap_id, group_id, ip, port, proto, node_type, display_name = record

                if current_group != group_id:
                    if current_group is not None:
                        logger.info("-" * 80)
                    logger.info(f"\nGroup {group_id}:")
                    current_group = group_id

                # Format node type
                if node_type == 1:
                    node_type_str = "Client"
                elif node_type == 2:
                    node_type_str = "Server"
                elif node_type == 1001:
                    node_type_str = "NetDevice(Client-Capture)"
                elif node_type == 1002:
                    node_type_str = "NetDevice(Capture-Server)"
                else:
                    node_type_str = f"Type{node_type}"

                port_str = f":{port}" if port else ""
                ip_str = ip if ip else "N/A"
                display_str = f" ({display_name})" if display_name else ""
                logger.info(f"  [{node_type_str}] pcap_id={pcap_id}, ip={ip_str}{port_str}, proto={proto}{display_str}")

            logger.info("-" * 80)

            # Count network device nodes
            db._cursor.execute(f"""
                SELECT COUNT(*) FROM {db.full_table_name}
                WHERE group_id IN (1, 2, 3) AND type IN (1001, 1002);
            """)
            net_device_count = db._cursor.fetchone()[0]
            logger.info(f"\n✓ Network device nodes inserted: {net_device_count}")

            # Clean up test records
            logger.info("\nCleaning up test records...")
            db._cursor.execute(f"""
                DELETE FROM {db.full_table_name}
                WHERE group_id IN (1, 2, 3);
            """)
            db.commit()
            logger.info("✓ Test records cleaned up")
            
        logger.info("\n✓ Test completed successfully!")
        return 0
        
    except ImportError as e:
        logger.error(f"Database functionality not available: {e}")
        logger.error("Install psycopg2-binary to enable database output: pip install psycopg2-binary")
        return 1
    except Exception as e:
        logger.error(f"Test failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(test_endpoint_stats_write())

