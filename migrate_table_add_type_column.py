#!/usr/bin/env python3
"""
Migrate kase_133_tcp_stream_extra table to add tcp_flags_different_type column at position 6.

This script will:
1. Create a new table with the correct column order
2. Copy all data from the old table
3. Drop the old table
4. Rename the new table
5. Recreate indexes and constraints
"""

import psycopg2

DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def migrate_table(table_name='kase_133_tcp_stream_extra'):
    """Migrate table to add tcp_flags_different_type at position 6."""
    print("=" * 120)
    print(f"MIGRATING TABLE: public.{table_name}")
    print("=" * 120)
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = False
        cursor = conn.cursor()
        
        # Step 1: Check if migration is needed
        print("\n1. Checking current table structure...")
        cursor.execute("""
            SELECT ordinal_position, column_name
            FROM information_schema.columns
            WHERE table_schema = 'public' 
            AND table_name = %s
            ORDER BY ordinal_position;
        """, (table_name,))
        
        columns = cursor.fetchall()
        print(f"   Current columns: {len(columns)}")
        for pos, name in columns:
            print(f"   Position {pos}: {name}")
        
        # Check if tcp_flags_different_type is at position 6
        cursor.execute("""
            SELECT ordinal_position
            FROM information_schema.columns
            WHERE table_schema = 'public' 
            AND table_name = %s
            AND column_name = 'tcp_flags_different_type';
        """, (table_name,))
        
        result = cursor.fetchone()
        if result and result[0] == 6:
            print("\n✅ Table already has correct structure. No migration needed.")
            cursor.close()
            conn.close()
            return
        
        print("\n⚠️  Migration needed: tcp_flags_different_type is not at position 6")
        
        # Step 2: Create new table with correct structure
        print("\n2. Creating new table with correct structure...")
        new_table_name = f"{table_name}_new"
        
        create_sql = f"""
            CREATE TABLE public.{new_table_name} (
                pcap_id integer,
                flow_hash bigint,
                first_time bigint,
                last_time bigint,
                tcp_flags_different_cnt bigint,
                tcp_flags_different_type text,
                tcp_flags_different_text text[],
                seq_num_different_cnt bigint,
                seq_num_different_text text[],
                id integer NOT NULL
            );
        """
        
        cursor.execute(create_sql)
        print(f"   ✅ Created table: public.{new_table_name}")
        
        # Step 3: Copy data from old table
        print("\n3. Copying data from old table...")
        
        # Check if tcp_flags_different_type column exists in old table
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.columns
                WHERE table_schema = 'public'
                AND table_name = %s
                AND column_name = 'tcp_flags_different_type'
            );
        """, (table_name,))
        
        has_type_column = cursor.fetchone()[0]
        
        if has_type_column:
            copy_sql = f"""
                INSERT INTO public.{new_table_name} (
                    pcap_id,
                    flow_hash,
                    first_time,
                    last_time,
                    tcp_flags_different_cnt,
                    tcp_flags_different_type,
                    tcp_flags_different_text,
                    seq_num_different_cnt,
                    seq_num_different_text,
                    id
                )
                SELECT 
                    pcap_id,
                    flow_hash,
                    first_time,
                    last_time,
                    tcp_flags_different_cnt,
                    tcp_flags_different_type,
                    tcp_flags_different_text,
                    seq_num_different_cnt,
                    seq_num_different_text,
                    id
                FROM public.{table_name};
            """
        else:
            copy_sql = f"""
                INSERT INTO public.{new_table_name} (
                    pcap_id,
                    flow_hash,
                    first_time,
                    last_time,
                    tcp_flags_different_cnt,
                    tcp_flags_different_type,
                    tcp_flags_different_text,
                    seq_num_different_cnt,
                    seq_num_different_text,
                    id
                )
                SELECT 
                    pcap_id,
                    flow_hash,
                    first_time,
                    last_time,
                    tcp_flags_different_cnt,
                    NULL,
                    tcp_flags_different_text,
                    seq_num_different_cnt,
                    seq_num_different_text,
                    id
                FROM public.{table_name};
            """
        
        cursor.execute(copy_sql)
        rows_copied = cursor.rowcount
        print(f"   ✅ Copied {rows_copied} rows")
        
        # Step 4: Drop old table
        print("\n4. Dropping old table...")
        cursor.execute(f"DROP TABLE public.{table_name} CASCADE;")
        print(f"   ✅ Dropped table: public.{table_name}")
        
        # Step 5: Rename new table
        print("\n5. Renaming new table...")
        cursor.execute(f"ALTER TABLE public.{new_table_name} RENAME TO {table_name};")
        print(f"   ✅ Renamed {new_table_name} to {table_name}")
        
        # Step 6: Create or reuse sequence for id column
        print("\n6. Setting up sequence for id column...")
        sequence_name = f"{table_name}_id_seq"

        # Check if sequence exists
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM pg_class
                WHERE relkind = 'S'
                AND relname = %s
                AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
            );
        """, (sequence_name,))

        sequence_exists = cursor.fetchone()[0]

        if not sequence_exists:
            cursor.execute(f"""
                CREATE SEQUENCE public.{sequence_name}
                    START WITH 1
                    INCREMENT BY 1
                    NO MINVALUE
                    NO MAXVALUE
                    CACHE 1;
            """)
            print(f"   ✅ Created sequence: {sequence_name}")
        else:
            print(f"   ℹ️  Sequence already exists: {sequence_name}")

        # Set the sequence to the max id + 1
        cursor.execute(f"SELECT MAX(id) FROM public.{table_name};")
        max_id = cursor.fetchone()[0] or 0
        cursor.execute(f"SELECT setval('public.{sequence_name}', {max_id + 1}, false);")
        print(f"   ✅ Set sequence value to {max_id + 1}")

        cursor.execute(f"ALTER SEQUENCE public.{sequence_name} OWNED BY public.{table_name}.id;")
        cursor.execute(f"ALTER TABLE ONLY public.{table_name} ALTER COLUMN id SET DEFAULT nextval('public.{sequence_name}'::regclass);")
        print(f"   ✅ Configured sequence for id column")
        
        # Step 7: Add primary key constraint
        print("\n7. Adding primary key constraint...")
        cursor.execute(f"ALTER TABLE ONLY public.{table_name} ADD CONSTRAINT {table_name}_pkey PRIMARY KEY (id);")
        print(f"   ✅ Added primary key constraint")
        
        # Step 8: Create indexes
        print("\n8. Creating indexes...")
        
        cursor.execute(f"CREATE INDEX idx_{table_name}_flow_hash ON public.{table_name} USING btree (flow_hash);")
        print(f"   ✅ Created index: idx_{table_name}_flow_hash")
        
        cursor.execute(f"CREATE INDEX idx_{table_name}_pcap_id ON public.{table_name} USING btree (pcap_id);")
        print(f"   ✅ Created index: idx_{table_name}_pcap_id")
        
        cursor.execute(f"CREATE INDEX idx_{table_name}_time ON public.{table_name} USING btree (first_time, last_time);")
        print(f"   ✅ Created index: idx_{table_name}_time")
        
        # Commit transaction
        print("\n9. Committing transaction...")
        conn.commit()
        print("   ✅ Transaction committed")
        
        # Verify final structure
        print("\n10. Verifying final structure...")
        cursor.execute("""
            SELECT ordinal_position, column_name
            FROM information_schema.columns
            WHERE table_schema = 'public' 
            AND table_name = %s
            ORDER BY ordinal_position;
        """, (table_name,))
        
        final_columns = cursor.fetchall()
        print(f"\n   Final column structure:")
        for pos, name in final_columns:
            marker = " ← NEW" if name == "tcp_flags_different_type" else ""
            print(f"   位置 {pos:<2}: {name}{marker}")
        
        print("\n" + "=" * 120)
        print("✅ ✅ ✅ MIGRATION COMPLETED SUCCESSFULLY! ✅ ✅ ✅")
        print("=" * 120)
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        if conn:
            conn.rollback()
            print("\n⚠️  Transaction rolled back")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        table_name = sys.argv[1]
    else:
        table_name = 'kase_133_tcp_stream_extra'
    
    print(f"\nMigrating table: {table_name}")
    print("This will restructure the table to add tcp_flags_different_type at position 6")
    
    response = input("\nDo you want to continue? (yes/no): ")
    if response.lower() in ['yes', 'y']:
        migrate_table(table_name)
    else:
        print("Migration cancelled.")

