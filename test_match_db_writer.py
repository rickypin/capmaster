#!/usr/bin/env python3
"""Test script for match plugin database writer."""

import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from capmaster.plugins.match.db_writer import MatchDatabaseWriter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def test_database_connection():
    """Test database connection and write some test records."""
    
    # Database connection parameters
    db_connection = "postgresql://postgres:password@172.16.200.156:5433/r2"
    kase_id = 137
    
    logger.info("=" * 80)
    logger.info("Testing Match Plugin Database Writer")
    logger.info("=" * 80)
    
    try:
        # Create database writer
        with MatchDatabaseWriter(db_connection, kase_id) as db:
            logger.info(f"Connected to database for kase_id={kase_id}")
            
            # Ensure table exists
            db.ensure_table_exists()
            
            # Insert test records
            logger.info("\nInserting test records...")
            
            # Test record 1: Client endpoint with IP and port
            db.insert_node(
                pcap_id=0,
                group_id=999,
                ip="192.168.1.100",
                port=54321,
                proto=6,  # TCP
                node_type=2,  # Client type
                is_capture=False,
                net_area=[1],
                stream_cnt=5,
                pktlen=12345,
                display_name="Test Client 1"
            )
            logger.info("✓ Inserted test record 1: Client endpoint")
            
            # Test record 2: Server endpoint
            db.insert_node(
                pcap_id=0,
                group_id=999,
                ip="10.0.0.50",
                port=443,
                proto=6,  # TCP
                node_type=1,  # Server type
                is_capture=False,
                net_area=[2],
                stream_cnt=5,
                pktlen=54321,
                display_name="Test Server 1"
            )
            logger.info("✓ Inserted test record 2: Server endpoint")
            
            # Test record 3: Network node without port
            db.insert_node(
                pcap_id=1,
                group_id=999,
                ip="172.16.0.1",
                port=None,
                proto=None,
                node_type=1001,  # Network node type
                is_capture=False,
                net_area=[],
                stream_cnt=0,
                pktlen=0,
                display_name="Test Network Node"
            )
            logger.info("✓ Inserted test record 3: Network node")
            
            # Test record 4: Virtual node
            db.insert_node(
                pcap_id=1,
                group_id=999,
                ip=None,
                port=None,
                proto=None,
                node_type=1002,  # Virtual node type
                is_capture=False,
                net_area=[],
                stream_cnt=0,
                pktlen=0,
                display_name="Test Virtual Node"
            )
            logger.info("✓ Inserted test record 4: Virtual node")
            
            # Commit all inserts
            db.commit()
            
            logger.info("\n" + "=" * 80)
            logger.info("✓ Successfully wrote 4 test records to database")
            logger.info("=" * 80)
            
            # Verify the records were inserted
            logger.info("\nVerifying inserted records...")
            db._cursor.execute(f"""
                SELECT id, pcap_id, group_id, ip, port, proto, type, stream_cnt, pktlen, display_name
                FROM {db.full_table_name}
                WHERE group_id = 999
                ORDER BY id;
            """)
            
            records = db._cursor.fetchall()
            logger.info(f"\nFound {len(records)} records with group_id=999:")
            logger.info("-" * 80)
            
            for record in records:
                id_, pcap_id, group_id, ip, port, proto, node_type, stream_cnt, pktlen, display_name = record
                logger.info(f"ID: {id_}")
                logger.info(f"  pcap_id={pcap_id}, group_id={group_id}")
                logger.info(f"  ip={ip}, port={port}, proto={proto}")
                logger.info(f"  type={node_type}, stream_cnt={stream_cnt}, pktlen={pktlen}")
                logger.info(f"  display_name='{display_name}'")
                logger.info("-" * 80)
            
            # Clean up test records
            logger.info("\nCleaning up test records...")
            db._cursor.execute(f"""
                DELETE FROM {db.full_table_name}
                WHERE group_id = 999;
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
    sys.exit(test_database_connection())

