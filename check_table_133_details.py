#!/usr/bin/env python3
"""Check detailed structure of kase_133_tcp_stream_extra table."""

import psycopg2

DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def check_table_133():
    """Check detailed structure of kase_133_tcp_stream_extra."""
    print("=" * 120)
    print("DETAILED STRUCTURE OF public.kase_133_tcp_stream_extra")
    print("=" * 120)
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        table_name = 'kase_133_tcp_stream_extra'
        
        # Get all columns with full details
        print("\n" + "=" * 120)
        print("ALL COLUMNS (ordered by position)")
        print("=" * 120)
        
        cursor.execute("""
            SELECT 
                ordinal_position,
                column_name,
                data_type,
                udt_name,
                character_maximum_length,
                numeric_precision,
                numeric_scale,
                is_nullable,
                column_default
            FROM information_schema.columns
            WHERE table_schema = 'public' 
            AND table_name = %s
            ORDER BY ordinal_position;
        """, (table_name,))
        
        columns = cursor.fetchall()
        
        print(f"\nTotal columns: {len(columns)}\n")
        print(f"{'Pos':<5} {'Column Name':<30} {'Data Type':<20} {'UDT Name':<20} {'Nullable':<10} {'Default':<30}")
        print("-" * 120)
        
        for col in columns:
            pos, name, dtype, udt, maxlen, prec, scale, nullable, default = col
            print(f"{pos:<5} {name:<30} {dtype:<20} {udt:<20} {nullable:<10} {str(default):<30}")
        
        # Check if there's an extra column
        print("\n" + "=" * 120)
        print("COLUMN NAME LIST")
        print("=" * 120)
        
        col_names = [col[1] for col in columns]
        for i, name in enumerate(col_names, 1):
            print(f"{i}. {name}")
        
        # Get table creation DDL
        print("\n" + "=" * 120)
        print("TABLE DEFINITION (from pg_catalog)")
        print("=" * 120)
        
        cursor.execute("""
            SELECT 
                a.attname as column_name,
                pg_catalog.format_type(a.atttypid, a.atttypmod) as data_type,
                a.attnotnull as not_null,
                a.attnum as position
            FROM pg_catalog.pg_attribute a
            WHERE a.attrelid = 'public.kase_133_tcp_stream_extra'::regclass
            AND a.attnum > 0 
            AND NOT a.attisdropped
            ORDER BY a.attnum;
        """)
        
        pg_columns = cursor.fetchall()
        
        print(f"\nColumns from pg_catalog: {len(pg_columns)}\n")
        print(f"{'Pos':<5} {'Column Name':<30} {'Data Type':<30} {'Not Null':<10}")
        print("-" * 120)
        
        for col in pg_columns:
            name, dtype, not_null, pos = col
            print(f"{pos:<5} {name:<30} {dtype:<30} {not_null}")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    check_table_133()

