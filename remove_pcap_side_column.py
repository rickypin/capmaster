#!/usr/bin/env python3
"""Remove pcap_side column from kase_133_tcp_stream_extra table."""

import psycopg2

DB_CONFIG = {
    'host': '172.16.200.156',
    'port': 5433,
    'database': 'r2',
    'user': 'postgres',
    'password': 'password'
}

def remove_pcap_side_column():
    """Remove pcap_side column from the table."""
    print("=" * 120)
    print("REMOVING PCAP_SIDE COLUMN")
    print("=" * 120)
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Check if pcap_side column exists
        print("\n1. Checking if pcap_side column exists...")
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.columns
                WHERE table_schema = 'public'
                AND table_name = 'kase_133_tcp_stream_extra'
                AND column_name = 'pcap_side'
            );
        """)
        
        exists = cursor.fetchone()[0]
        
        if exists:
            print("   ✅ pcap_side column exists")
            
            # Show current structure
            print("\n2. Current table structure:")
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
                marker = " ← TO BE REMOVED" if name == "pcap_side" else ""
                print(f"   {pos:<5} {name:<35} {dtype:<20}{marker}")
            
            print(f"\n   Total columns: {len(columns)}")
            
            # Ask for confirmation
            print("\n3. Removing pcap_side column...")
            response = input("\n   Are you sure you want to remove the pcap_side column? (yes/no): ")
            
            if response.lower() == 'yes':
                # Remove the column
                cursor.execute("""
                    ALTER TABLE public.kase_133_tcp_stream_extra
                    DROP COLUMN pcap_side;
                """)
                
                conn.commit()
                print("\n   ✅ Column pcap_side removed successfully!")
                
                # Show updated structure
                print("\n4. Updated table structure:")
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
                
            else:
                print("\n   ❌ Operation cancelled")
                
        else:
            print("   ℹ️  pcap_side column does NOT exist (already removed or never existed)")
        
        print("\n" + "=" * 120)
        print("OPERATION COMPLETED")
        print("=" * 120)
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    remove_pcap_side_column()

