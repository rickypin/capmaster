#!/usr/bin/env python3
"""Verify the updated table structure with tcp_flags_different_type column."""

import psycopg2

DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def verify_structure():
    """Verify the table structure matches the expected schema."""
    print("=" * 120)
    print("VERIFYING TABLE STRUCTURE: public.kase_133_tcp_stream_extra")
    print("=" * 120)
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Get column information
        cursor.execute("""
            SELECT 
                ordinal_position,
                column_name,
                data_type,
                udt_name,
                is_nullable,
                column_default
            FROM information_schema.columns
            WHERE table_schema = 'public' 
            AND table_name = 'kase_133_tcp_stream_extra'
            ORDER BY ordinal_position;
        """)
        
        columns = cursor.fetchall()
        
        print("\n📋 TABLE COLUMNS:")
        print("-" * 120)
        print(f"{'Pos':<5} {'Column Name':<35} {'Data Type':<20} {'Nullable':<10} {'Default':<30}")
        print("-" * 120)
        
        expected_columns = [
            (1, 'pcap_id', 'integer', 'int4', 'YES', None),
            (2, 'flow_hash', 'bigint', 'int8', 'YES', None),
            (3, 'first_time', 'bigint', 'int8', 'YES', None),
            (4, 'last_time', 'bigint', 'int8', 'YES', None),
            (5, 'tcp_flags_different_cnt', 'bigint', 'int8', 'YES', None),
            (6, 'tcp_flags_different_type', 'text', 'text', 'YES', None),
            (7, 'tcp_flags_different_text', 'ARRAY', '_varchar', 'YES', None),
            (8, 'seq_num_different_cnt', 'bigint', 'int8', 'YES', None),
            (9, 'seq_num_different_text', 'ARRAY', '_varchar', 'YES', None),
            (10, 'id', 'integer', 'int4', 'NO', 'nextval'),
        ]
        
        all_match = True
        
        for i, col in enumerate(columns):
            pos, name, dtype, udt, nullable, default = col
            print(f"{pos:<5} {name:<35} {dtype:<20} {nullable:<10} {str(default)[:30] if default else '':<30}")
            
            # Check if matches expected
            if i < len(expected_columns):
                exp_pos, exp_name, exp_dtype, exp_udt, exp_nullable, exp_default = expected_columns[i]
                
                if name != exp_name:
                    print(f"      ❌ Expected column name: {exp_name}")
                    all_match = False
                elif pos != exp_pos:
                    print(f"      ❌ Expected position: {exp_pos}")
                    all_match = False
                elif dtype != exp_dtype:
                    print(f"      ❌ Expected data type: {exp_dtype}")
                    all_match = False
                else:
                    print(f"      ✅ Matches expected schema")
        
        print("-" * 120)
        
        # Verify the new column exists
        print("\n🔍 CHECKING NEW COLUMN:")
        print("-" * 120)
        
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.columns
                WHERE table_schema = 'public'
                AND table_name = 'kase_133_tcp_stream_extra'
                AND column_name = 'tcp_flags_different_type'
                AND ordinal_position = 6
            );
        """)
        
        has_new_column = cursor.fetchone()[0]
        
        if has_new_column:
            print("✅ Column 'tcp_flags_different_type' exists at position 6")
        else:
            print("❌ Column 'tcp_flags_different_type' NOT found at position 6")
            all_match = False
        
        # Check data in the new column
        print("\n📊 SAMPLE DATA FROM NEW COLUMN:")
        print("-" * 120)
        
        cursor.execute("""
            SELECT 
                id,
                tcp_flags_different_type,
                tcp_flags_different_cnt
            FROM public.kase_133_tcp_stream_extra
            WHERE tcp_flags_different_type IS NOT NULL
            ORDER BY id DESC
            LIMIT 3;
        """)
        
        rows = cursor.fetchall()
        
        if rows:
            print(f"{'ID':<10} {'TCP Flags Type':<30} {'Count':<10}")
            print("-" * 120)
            for row in rows:
                id, flags_type, count = row
                print(f"{id:<10} {flags_type:<30} {count:<10}")
            print(f"\n✅ Found {len(rows)} record(s) with tcp_flags_different_type data")
        else:
            print("⚠️  No records found with tcp_flags_different_type data")
        
        # Final summary
        print("\n" + "=" * 120)
        print("SUMMARY")
        print("=" * 120)
        
        if all_match and has_new_column:
            print("\n✅ ✅ ✅ TABLE STRUCTURE IS CORRECT! ✅ ✅ ✅")
            print("\nExpected schema:")
            print("  位置 1:  pcap_id")
            print("  位置 2:  flow_hash")
            print("  位置 3:  first_time")
            print("  位置 4:  last_time")
            print("  位置 5:  tcp_flags_different_cnt")
            print("  位置 6:  tcp_flags_different_type  ← NEW COLUMN")
            print("  位置 7:  tcp_flags_different_text")
            print("  位置 8:  seq_num_different_cnt")
            print("  位置 9:  seq_num_different_text")
            print("  位置 10: id")
        else:
            print("\n❌ TABLE STRUCTURE HAS ISSUES - See details above")
        
        print("=" * 120)
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    verify_structure()

