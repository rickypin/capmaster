#!/usr/bin/env python3
"""Detailed view of tcp_stream_extra table."""

import sys
import psycopg2
from psycopg2 import OperationalError
from datetime import datetime

# Database connection parameters
DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def format_timestamp(ns_timestamp):
    """Convert nanosecond timestamp to readable format."""
    if ns_timestamp is None:
        return "N/A"
    try:
        # Convert nanoseconds to seconds
        seconds = ns_timestamp / 1_000_000_000
        dt = datetime.fromtimestamp(seconds)
        return dt.strftime('%Y-%m-%d %H:%M:%S.%f')
    except:
        return str(ns_timestamp)

def detailed_view():
    """Show detailed view of tcp_stream_extra table."""
    print("=" * 100)
    print("DETAILED VIEW: public.kase_134_tcp_stream_extra")
    print("=" * 100)
    
    try:
        conn = psycopg2.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            database=DB_CONFIG['database'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            connect_timeout=10
        )
        
        cursor = conn.cursor()
        
        # Get all data
        cursor.execute("SELECT * FROM public.kase_134_tcp_stream_extra ORDER BY id;")
        rows = cursor.fetchall()
        col_names = [desc[0] for desc in cursor.description]
        
        print(f"\n📊 Total Records: {len(rows)}\n")
        
        # Display each record in detail
        for idx, row in enumerate(rows, 1):
            print(f"{'─' * 100}")
            print(f"RECORD #{idx}")
            print(f"{'─' * 100}")
            
            for col_name, value in zip(col_names, row):
                if col_name in ['first_time', 'last_time']:
                    readable_time = format_timestamp(value)
                    print(f"  {col_name:<30}: {value} ({readable_time})")
                elif col_name in ['tcp_flags_different_text', 'seq_num_different_text']:
                    if value:
                        print(f"  {col_name:<30}: {value} (length: {len(value)})")
                    else:
                        print(f"  {col_name:<30}: [] (empty array)")
                else:
                    print(f"  {col_name:<30}: {value}")
            
            # Calculate duration if both timestamps exist
            if len(row) >= 4 and row[2] is not None and row[3] is not None:
                duration_ns = row[3] - row[2]
                duration_ms = duration_ns / 1_000_000
                print(f"\n  {'Duration':<30}: {duration_ns} ns ({duration_ms:.3f} ms)")
            
            print()
        
        # Show summary statistics
        print(f"{'═' * 100}")
        print("SUMMARY STATISTICS")
        print(f"{'═' * 100}\n")
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total_records,
                COUNT(DISTINCT pcap_id) as unique_pcap_ids,
                COUNT(DISTINCT flow_hash) as unique_flow_hashes,
                MIN(first_time) as earliest_time,
                MAX(last_time) as latest_time,
                SUM(tcp_flags_different_cnt) as total_tcp_flags_diff,
                SUM(seq_num_different_cnt) as total_seq_num_diff
            FROM public.kase_134_tcp_stream_extra;
        """)
        
        stats = cursor.fetchone()
        
        print(f"  Total Records              : {stats[0]}")
        print(f"  Unique PCAP IDs            : {stats[1]}")
        print(f"  Unique Flow Hashes         : {stats[2]}")
        print(f"  Earliest Timestamp         : {format_timestamp(stats[3])}")
        print(f"  Latest Timestamp           : {format_timestamp(stats[4])}")
        print(f"  Total TCP Flags Different  : {stats[5] if stats[5] else 0}")
        print(f"  Total Seq Num Different    : {stats[6] if stats[6] else 0}")
        
        # Check if there's a related tcp_stream table
        print(f"\n{'═' * 100}")
        print("RELATED TABLES CHECK")
        print(f"{'═' * 100}\n")
        
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name LIKE 'kase_134_%'
            ORDER BY table_name;
        """)
        
        related_tables = cursor.fetchall()
        print(f"  Found {len(related_tables)} related tables for kase_134:\n")
        for (table_name,) in related_tables:
            cursor.execute(f"SELECT COUNT(*) FROM public.{table_name};")
            count = cursor.fetchone()[0]
            print(f"    - {table_name:<40} ({count} rows)")
        
        print(f"\n{'═' * 100}")
        print("✅ Query completed successfully!")
        print(f"{'═' * 100}\n")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"❌ Error: {type(e).__name__}: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    detailed_view()

