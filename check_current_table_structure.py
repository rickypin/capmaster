#!/usr/bin/env python3
"""Check current table structure."""

import psycopg2

DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def check_structure():
    """Check table structure."""
    print("=" * 120)
    print("CHECKING CURRENT TABLE STRUCTURE")
    print("=" * 120)
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Check kase_133_tcp_stream_extra structure
        print("\n1. Current kase_133_tcp_stream_extra structure:")
        cursor.execute("""
            SELECT 
                ordinal_position,
                column_name,
                data_type,
                is_nullable
            FROM information_schema.columns
            WHERE table_schema = 'public'
            AND table_name = 'kase_133_tcp_stream_extra'
            ORDER BY ordinal_position;
        """)
        
        columns = cursor.fetchall()
        print(f"\n   {'Pos':<5} {'Column Name':<35} {'Data Type':<20} {'Nullable':<10}")
        print("   " + "-" * 70)
        
        for pos, name, dtype, nullable in columns:
            print(f"   {pos:<5} {name:<35} {dtype:<20} {nullable:<10}")
        
        print(f"\n   Total columns: {len(columns)}")
        
        # Expected structure from code
        print("\n2. Expected structure from code (10 columns):")
        expected = [
            (1, "pcap_id", "integer"),
            (2, "flow_hash", "bigint"),
            (3, "first_time", "bigint"),
            (4, "last_time", "bigint"),
            (5, "tcp_flags_different_cnt", "bigint"),
            (6, "tcp_flags_different_type", "text"),
            (7, "tcp_flags_different_text", "text[]"),
            (8, "seq_num_different_cnt", "bigint"),
            (9, "seq_num_different_text", "text[]"),
            (10, "id", "integer"),
        ]
        
        print(f"\n   {'Pos':<5} {'Column Name':<35} {'Data Type':<20}")
        print("   " + "-" * 60)
        
        for pos, name, dtype in expected:
            print(f"   {pos:<5} {name:<35} {dtype:<20}")
        
        # Compare
        print("\n3. Comparison:")
        current_cols = {col[1]: (col[0], col[2]) for col in columns}
        expected_cols = {col[1]: (col[0], col[2]) for col in expected}
        
        # Find extra columns in current table
        extra = set(current_cols.keys()) - set(expected_cols.keys())
        if extra:
            print(f"\n   ⚠️  Extra columns in current table: {extra}")
            for col in extra:
                pos, dtype = current_cols[col]
                print(f"      - {col} (position {pos}, type {dtype})")
        
        # Find missing columns in current table
        missing = set(expected_cols.keys()) - set(current_cols.keys())
        if missing:
            print(f"\n   ❌ Missing columns in current table: {missing}")
            for col in missing:
                pos, dtype = expected_cols[col]
                print(f"      - {col} (expected position {pos}, type {dtype})")
        
        if not extra and not missing:
            print("\n   ✅ Table structure matches expected structure")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    check_structure()

