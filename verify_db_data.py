#!/usr/bin/env python3
"""Verify data was written to database."""

import psycopg2

DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def verify_data():
    """Query and display the latest records from kase_133_tcp_stream_extra."""
    print("=" * 100)
    print("Verifying Data in public.kase_133_tcp_stream_extra")
    print("=" * 100)
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Get total row count
        cursor.execute("SELECT COUNT(*) FROM public.kase_133_tcp_stream_extra;")
        total_rows = cursor.fetchone()[0]
        print(f"\n📊 Total rows in table: {total_rows}")
        
        if total_rows == 0:
            print("\n⚠️  Table is empty")
            return
        
        # Get latest 5 records
        print("\n📄 Latest 5 records:")
        print("-" * 100)
        
        cursor.execute("""
            SELECT
                id,
                pcap_id,
                flow_hash,
                first_time,
                last_time,
                tcp_flags_different_cnt,
                tcp_flags_different_type,
                tcp_flags_different_text,
                seq_num_different_cnt,
                seq_num_different_text
            FROM public.kase_133_tcp_stream_extra
            ORDER BY id DESC
            LIMIT 5;
        """)

        rows = cursor.fetchall()

        for row in rows:
            (id, pcap_id, flow_hash, first_time, last_time,
             tcp_flags_cnt, tcp_flags_type, tcp_flags_text, seq_num_cnt, seq_num_text) = row

            print(f"\n{'='*100}")
            print(f"Record ID: {id}")
            print(f"{'='*100}")
            print(f"  PCAP ID:                    {pcap_id}")
            print(f"  Flow Hash:                  {flow_hash}")
            print(f"  First Time:                 {first_time}")
            print(f"  Last Time:                  {last_time}")
            print(f"  TCP Flags Different Count:  {tcp_flags_cnt}")
            print(f"  TCP Flags Different Type:   {tcp_flags_type}")
            print(f"  TCP Flags Different Text:   {tcp_flags_text}")
            print(f"  Seq Num Different Count:    {seq_num_cnt}")
            print(f"  Seq Num Different Text:     {seq_num_text}")
        
        print("\n" + "=" * 100)
        print("✅ Verification completed successfully!")
        print("=" * 100)
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")

if __name__ == "__main__":
    verify_data()

