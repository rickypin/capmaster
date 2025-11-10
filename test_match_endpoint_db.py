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
        # Create test endpoint statistics (simulating the output from your example)
        endpoint_stats = [
            EndpointPairStats(
                tuple_a=EndpointTuple(
                    client_ip="8.42.96.45",
                    server_ip="8.67.2.125",
                    server_port=26302,
                ),
                tuple_b=EndpointTuple(
                    client_ip="8.42.96.45",
                    server_ip="8.67.2.125",
                    server_port=26302,
                ),
                count=1,
                confidence="VERY_LOW",
            ),
            EndpointPairStats(
                tuple_a=EndpointTuple(
                    client_ip="8.67.2.125",
                    server_ip="8.42.96.45",
                    server_port=35101,
                ),
                tuple_b=EndpointTuple(
                    client_ip="8.67.2.125",
                    server_ip="8.42.96.45",
                    server_port=35101,
                ),
                count=1,
                confidence="VERY_LOW",
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
                WHERE group_id IN (1, 2)
                ORDER BY group_id, pcap_id, type;
            """)
            
            records = db._cursor.fetchall()
            logger.info(f"\nFound {len(records)} records with group_id IN (1, 2):")
            logger.info("-" * 80)
            
            current_group = None
            for record in records:
                id_, pcap_id, group_id, ip, port, proto, node_type, display_name = record
                
                if current_group != group_id:
                    if current_group is not None:
                        logger.info("-" * 80)
                    logger.info(f"\nGroup {group_id}:")
                    current_group = group_id
                
                node_type_str = "Client" if node_type == 1 else "Server" if node_type == 2 else f"Type{node_type}"
                port_str = f":{port}" if port else ""
                logger.info(f"  [{node_type_str}] pcap_id={pcap_id}, ip={ip}{port_str}, proto={proto}")
            
            logger.info("-" * 80)
            
            # Clean up test records
            logger.info("\nCleaning up test records...")
            db._cursor.execute(f"""
                DELETE FROM {db.full_table_name}
                WHERE group_id IN (1, 2);
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

