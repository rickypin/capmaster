#!/usr/bin/env python3
"""Verify latest data in the database."""

import psycopg2

DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def verify_data():
    """Verify latest data."""
    print("=" * 120)
    print("VERIFYING LATEST DATA")
    print("=" * 120)
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Get latest records
        print("\n1. Latest 5 records in kase_133_tcp_stream_extra:")
        cursor.execute("""
            SELECT 
                id, 
                pcap_id, 
                flow_hash,
                tcp_flags_different_cnt,
                tcp_flags_different_type,
                tcp_flags_different_text
            FROM public.kase_133_tcp_stream_extra
            ORDER BY id DESC
            LIMIT 5;
        """)
        
        records = cursor.fetchall()
        
        if records:
            print(f"\n   Found {len(records)} record(s):\n")
            
            for id, pcap_id, flow_hash, tcp_cnt, tcp_type, tcp_text in records:
                print(f"   Record ID: {id}")
                print(f"   - PCAP ID: {pcap_id}")
                print(f"   - Flow Hash: {flow_hash}")
                print(f"   - TCP Flags Count: {tcp_cnt}")
                print(f"   - TCP Flags Type: {tcp_type}")
                print(f"   - TCP Flags Text: {tcp_text[:2] if tcp_text else None}...")
                print()
        else:
            print("   No records found")
        
        # Count total records
        print("\n2. Total records in table:")
        cursor.execute("""
            SELECT COUNT(*) 
            FROM public.kase_133_tcp_stream_extra;
        """)
        
        count = cursor.fetchone()[0]
        print(f"   Total records: {count}")
        
        # Verify table structure
        print("\n3. Current table structure:")
        cursor.execute("""
            SELECT 
                ordinal_position,
                column_name,
                data_type
            FROM information_schema.columns
            WHERE table_schema = 'public'
            AND table_name = 'kase_133_tcp_stream_extra'
            ORDER BY ordinal_position;
        """)
        
        columns = cursor.fetchall()
        print(f"\n   {'Pos':<5} {'Column Name':<35} {'Data Type':<20}")
        print("   " + "-" * 60)
        
        for pos, name, dtype in columns:
            print(f"   {pos:<5} {name:<35} {dtype:<20}")
        
        print(f"\n   Total columns: {len(columns)}")
        
        print("\n" + "=" * 120)
        print("VERIFICATION COMPLETED")
        print("=" * 120)
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    verify_data()

