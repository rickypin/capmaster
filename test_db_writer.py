#!/usr/bin/env python3
"""Test database writer functionality."""

from capmaster.plugins.compare.db_writer import DatabaseWriter

# Test connection string (update with your actual database)
DB_CONNECTION = "postgresql://postgres:password@172.16.200.156:5433/r2"
KASE_ID = 133

def test_db_writer():
    """Test database writer with sample data."""
    print("=" * 80)
    print("Testing Database Writer")
    print("=" * 80)
    
    try:
        print(f"\n1. Creating DatabaseWriter instance...")
        print(f"   Connection: {DB_CONNECTION}")
        print(f"   Kase ID: {KASE_ID}")
        print(f"   Table: public.kase_{KASE_ID}_tcp_stream_extra")
        
        with DatabaseWriter(DB_CONNECTION, KASE_ID) as db:
            print("\n2. ✅ Connected to database successfully")
            
            print("\n3. Ensuring table exists...")
            db.ensure_table_exists()
            print("   ✅ Table ready")
            
            print("\n4. Inserting test record...")
            db.insert_flow_hash(
                pcap_id=0,
                flow_hash=-1173584886679544929,
                first_time=None,
                last_time=None,
                tcp_flags_different_cnt=69,
                tcp_flags_different_type="0x0002->0x0010",
                tcp_flags_different_text=["0x0002→0x0010 (69 occurrences)"],
                seq_num_different_cnt=69,
                seq_num_different_text=[
                    "Frame 135→136: 123→456",
                    "Frame 136→137: 789→012",
                    "... and 64 more"
                ],
            )
            print("   ✅ Record inserted")
            
            print("\n5. Committing transaction...")
            db.commit()
            print("   ✅ Transaction committed")
            
        print("\n" + "=" * 80)
        print("✅ Test completed successfully!")
        print("=" * 80)
        print("\nTo verify the data was inserted, run:")
        print(f"  SELECT * FROM public.kase_{KASE_ID}_tcp_stream_extra ORDER BY id DESC LIMIT 5;")
        
    except ImportError as e:
        print(f"\n❌ Import Error: {e}")
        print("   Install psycopg2-binary: pip install psycopg2-binary")
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        print("\nPossible issues:")
        print("  - Database server is not accessible")
        print("  - Incorrect connection string")
        print("  - Firewall blocking connection")
        print("  - Invalid credentials")

if __name__ == "__main__":
    test_db_writer()

