#!/usr/bin/env python3
"""Clear the topological_graph table for kase 163."""

import sys
import psycopg2
from psycopg2 import sql


def clear_table(connection_string: str, kase_id: int) -> None:
    """
    Clear all records from the topological_graph table for a specific kase.
    
    Args:
        connection_string: PostgreSQL connection string
        kase_id: Case ID (e.g., 163)
    """
    table_name = f"kase_{kase_id}_topological_graph"
    full_table_name = f"public.{table_name}"
    
    print(f"Connecting to database...")
    
    try:
        # Connect to database
        conn = psycopg2.connect(connection_string)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = %s
            );
        """, (table_name,))
        
        exists = cursor.fetchone()[0]
        
        if not exists:
            print(f"❌ Table {full_table_name} does not exist!")
            return
        
        # Get current record count
        cursor.execute(f"SELECT COUNT(*) FROM {full_table_name};")
        count_before = cursor.fetchone()[0]
        
        print(f"📊 Table {full_table_name} currently has {count_before} records")
        
        if count_before == 0:
            print(f"✅ Table is already empty, nothing to clear")
            return
        
        # Confirm deletion
        print(f"\n⚠️  About to delete {count_before} records from {full_table_name}")
        response = input("Continue? (yes/no): ")
        
        if response.lower() not in ['yes', 'y']:
            print("❌ Operation cancelled")
            return
        
        # Delete all records
        print(f"\n🗑️  Deleting all records from {full_table_name}...")
        cursor.execute(f"DELETE FROM {full_table_name};")
        
        # Get new record count
        cursor.execute(f"SELECT COUNT(*) FROM {full_table_name};")
        count_after = cursor.fetchone()[0]
        
        # Commit transaction
        conn.commit()
        
        print(f"✅ Successfully deleted {count_before - count_after} records")
        print(f"📊 Table {full_table_name} now has {count_after} records")
        
        # Reset sequence (optional, for clean ID numbering)
        sequence_name = f"{table_name}_id_seq"
        print(f"\n🔄 Resetting sequence {sequence_name}...")
        cursor.execute(f"ALTER SEQUENCE public.{sequence_name} RESTART WITH 1;")
        conn.commit()
        print(f"✅ Sequence reset to 1")
        
        cursor.close()
        conn.close()
        
        print(f"\n✅ All done!")
        
    except psycopg2.Error as e:
        print(f"❌ Database error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


def main():
    """Main entry point."""
    print("=" * 80)
    print("Clear Topological Graph Table for Kase 163")
    print("=" * 80)
    print()

    # Check if connection string is provided as argument
    if len(sys.argv) > 1:
        connection_string = sys.argv[1]
        print(f"Using connection string from argument")
    else:
        # Interactive mode - ask for connection details
        print("Please provide database connection details:")
        print()

        host = input("Host [localhost]: ").strip() or "localhost"
        port = input("Port [5432]: ").strip() or "5432"
        database = input("Database [capmaster]: ").strip() or "capmaster"
        user = input("User [postgres]: ").strip() or "postgres"
        password = input("Password: ").strip()

        connection_string = f"postgresql://{user}:{password}@{host}:{port}/{database}"

    print()
    print(f"Connection: {connection_string.split('@')[1] if '@' in connection_string else 'localhost'}")
    print()

    clear_table(connection_string, kase_id=163)


if __name__ == "__main__":
    main()

