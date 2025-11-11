#!/usr/bin/env python3
"""
Clear all records from a topological_graph table.

Usage:
    python scripts/clear_topological_graph.py <connection_string> <kase_id>

Example:
    python scripts/clear_topological_graph.py "postgresql://user:pass@localhost:5432/dbname" 163
"""

import sys
from urllib.parse import urlparse


def clear_table(connection_string: str, kase_id: int) -> None:
    """
    Clear all records from the topological_graph table.
    
    Args:
        connection_string: PostgreSQL connection string
        kase_id: Case ID for table name
    """
    try:
        import psycopg2
    except ImportError:
        print("Error: psycopg2-binary is not installed")
        print("Install with: pip install psycopg2-binary")
        sys.exit(1)
    
    table_name = f"kase_{kase_id}_topological_graph"
    full_table_name = f"public.{table_name}"
    
    # Parse connection string
    parsed = urlparse(connection_string)
    
    try:
        # Connect to database
        conn = psycopg2.connect(
            host=parsed.hostname,
            port=parsed.port or 5432,
            database=parsed.path.lstrip('/'),
            user=parsed.username,
            password=parsed.password,
            connect_timeout=10
        )
        cursor = conn.cursor()
        
        print(f"Connected to database: {parsed.hostname}:{parsed.port}/{parsed.path.lstrip('/')}")
        
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
            print(f"Error: Table {full_table_name} does not exist")
            cursor.close()
            conn.close()
            sys.exit(1)
        
        # Count records before deletion
        cursor.execute(f"SELECT COUNT(*) FROM {full_table_name};")
        count_before = cursor.fetchone()[0]
        print(f"Records before deletion: {count_before}")
        
        if count_before == 0:
            print("Table is already empty")
            cursor.close()
            conn.close()
            return
        
        # Delete all records
        print(f"Deleting all records from {full_table_name}...")
        cursor.execute(f"DELETE FROM {full_table_name};")
        
        # Commit the transaction
        conn.commit()
        
        # Count records after deletion
        cursor.execute(f"SELECT COUNT(*) FROM {full_table_name};")
        count_after = cursor.fetchone()[0]
        
        print(f"Records after deletion: {count_after}")
        print(f"Successfully deleted {count_before} records from {full_table_name}")
        
        # Close connection
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def main():
    """Main entry point."""
    if len(sys.argv) != 3:
        print("Usage: python scripts/clear_topological_graph.py <connection_string> <kase_id>")
        print()
        print("Example:")
        print('  python scripts/clear_topological_graph.py "postgresql://user:pass@localhost:5432/dbname" 163')
        sys.exit(1)
    
    connection_string = sys.argv[1]
    try:
        kase_id = int(sys.argv[2])
    except ValueError:
        print(f"Error: kase_id must be an integer, got: {sys.argv[2]}")
        sys.exit(1)
    
    clear_table(connection_string, kase_id)


if __name__ == "__main__":
    main()

