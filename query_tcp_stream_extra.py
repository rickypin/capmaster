#!/usr/bin/env python3
"""Query tables with tcp_stream_extra in their name."""

import sys
import psycopg2
from psycopg2 import OperationalError

# Database connection parameters
DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def query_tcp_stream_extra_tables():
    """Find and display structure and content of tcp_stream_extra tables."""
    print("=" * 80)
    print("Searching for tables with 'tcp_stream_extra' in name")
    print("=" * 80)
    
    try:
        # Connect to database
        conn = psycopg2.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            database=DB_CONFIG['database'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            connect_timeout=10
        )
        
        cursor = conn.cursor()
        
        # Find tables with tcp_stream_extra in name
        print("\n🔍 Searching for tables...")
        cursor.execute("""
            SELECT table_schema, table_name 
            FROM information_schema.tables 
            WHERE table_name LIKE '%tcp_stream_extra%'
            ORDER BY table_schema, table_name;
        """)
        
        tables = cursor.fetchall()
        
        if not tables:
            print("❌ No tables found with 'tcp_stream_extra' in name")
            cursor.close()
            conn.close()
            return
        
        print(f"\n✅ Found {len(tables)} table(s):\n")
        for schema, table in tables:
            print(f"   - {schema}.{table}")
        
        # For each table, show structure and content
        for schema, table in tables:
            full_table_name = f"{schema}.{table}"
            print("\n" + "=" * 80)
            print(f"TABLE: {full_table_name}")
            print("=" * 80)
            
            # Get table structure
            print("\n📋 TABLE STRUCTURE:")
            print("-" * 80)
            cursor.execute(f"""
                SELECT 
                    column_name,
                    data_type,
                    character_maximum_length,
                    is_nullable,
                    column_default
                FROM information_schema.columns
                WHERE table_schema = %s AND table_name = %s
                ORDER BY ordinal_position;
            """, (schema, table))
            
            columns = cursor.fetchall()
            
            print(f"{'Column Name':<30} {'Data Type':<20} {'Nullable':<10} {'Default':<20}")
            print("-" * 80)
            for col_name, data_type, max_length, nullable, default in columns:
                if max_length:
                    type_str = f"{data_type}({max_length})"
                else:
                    type_str = data_type
                default_str = str(default)[:20] if default else ""
                print(f"{col_name:<30} {type_str:<20} {nullable:<10} {default_str:<20}")
            
            # Get row count
            cursor.execute(f"SELECT COUNT(*) FROM {full_table_name};")
            row_count = cursor.fetchone()[0]
            print(f"\n📊 Total rows: {row_count}")
            
            # Get table content (limit to 100 rows)
            if row_count > 0:
                print(f"\n📄 TABLE CONTENT (showing up to 100 rows):")
                print("-" * 80)
                
                cursor.execute(f"SELECT * FROM {full_table_name} LIMIT 100;")
                rows = cursor.fetchall()
                
                # Get column names
                col_names = [desc[0] for desc in cursor.description]
                
                # Print header
                header = " | ".join([f"{name:<20}" for name in col_names])
                print(header)
                print("-" * len(header))
                
                # Print rows
                for row in rows:
                    row_str = " | ".join([f"{str(val):<20}" for val in row])
                    print(row_str)
                
                if row_count > 100:
                    print(f"\n... ({row_count - 100} more rows not shown)")
            else:
                print("\n⚠️  Table is empty (no rows)")
            
            # Get indexes
            print(f"\n🔑 INDEXES:")
            print("-" * 80)
            cursor.execute(f"""
                SELECT
                    indexname,
                    indexdef
                FROM pg_indexes
                WHERE schemaname = %s AND tablename = %s
                ORDER BY indexname;
            """, (schema, table))
            
            indexes = cursor.fetchall()
            if indexes:
                for idx_name, idx_def in indexes:
                    print(f"\n{idx_name}:")
                    print(f"  {idx_def}")
            else:
                print("No indexes found")
            
            # Get constraints
            print(f"\n🔒 CONSTRAINTS:")
            print("-" * 80)
            cursor.execute(f"""
                SELECT
                    conname,
                    contype,
                    pg_get_constraintdef(oid) as definition
                FROM pg_constraint
                WHERE conrelid = %s::regclass
                ORDER BY conname;
            """, (full_table_name,))
            
            constraints = cursor.fetchall()
            if constraints:
                for con_name, con_type, con_def in constraints:
                    type_map = {
                        'p': 'PRIMARY KEY',
                        'f': 'FOREIGN KEY',
                        'u': 'UNIQUE',
                        'c': 'CHECK'
                    }
                    con_type_str = type_map.get(con_type, con_type)
                    print(f"\n{con_name} ({con_type_str}):")
                    print(f"  {con_def}")
            else:
                print("No constraints found")
        
        print("\n" + "=" * 80)
        print("✅ Query completed successfully!")
        print("=" * 80)
        
        cursor.close()
        conn.close()
        
    except OperationalError as e:
        print(f"❌ Database connection failed!")
        print(f"\n🔴 Error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error occurred!")
        print(f"\n🔴 Error: {type(e).__name__}: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    query_tcp_stream_extra_tables()

