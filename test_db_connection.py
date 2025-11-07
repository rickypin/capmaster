#!/usr/bin/env python3
"""Test PostgreSQL database connection."""

import sys

try:
    import psycopg2
    from psycopg2 import OperationalError
except ImportError:
    print("❌ psycopg2 is not installed.")
    print("Installing psycopg2-binary...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psycopg2-binary"])
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

def test_connection():
    """Test database connection and display basic information."""
    print("=" * 60)
    print("PostgreSQL Database Connection Test")
    print("=" * 60)
    print(f"\n📍 Connection Details:")
    print(f"   Host: {DB_CONFIG['host']}")
    print(f"   Port: {DB_CONFIG['port']}")
    print(f"   Database: {DB_CONFIG['database']}")
    print(f"   User: {DB_CONFIG['user']}")
    print(f"\n🔄 Attempting to connect...")
    
    try:
        # Attempt connection
        conn = psycopg2.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            database=DB_CONFIG['database'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            connect_timeout=10
        )
        
        print("✅ Connection successful!\n")
        
        # Get database version
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        db_version = cursor.fetchone()[0]
        print(f"📊 Database Version:")
        print(f"   {db_version}\n")
        
        # Get current database name
        cursor.execute("SELECT current_database();")
        current_db = cursor.fetchone()[0]
        print(f"📁 Current Database: {current_db}\n")
        
        # Get list of tables
        cursor.execute("""
            SELECT table_schema, table_name 
            FROM information_schema.tables 
            WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
            ORDER BY table_schema, table_name;
        """)
        tables = cursor.fetchall()
        
        if tables:
            print(f"📋 Tables in database ({len(tables)} found):")
            for schema, table in tables:
                print(f"   - {schema}.{table}")
        else:
            print("📋 No user tables found in database")
        
        print("\n" + "=" * 60)
        print("✅ Database connection test completed successfully!")
        print("=" * 60)
        
        # Close cursor and connection
        cursor.close()
        conn.close()
        
        return True
        
    except OperationalError as e:
        print(f"❌ Connection failed!")
        print(f"\n🔴 Error Details:")
        print(f"   {str(e)}")
        print("\n💡 Possible issues:")
        print("   - Database server is not running")
        print("   - Incorrect host/port")
        print("   - Firewall blocking connection")
        print("   - Invalid credentials")
        print("   - Database does not exist")
        print("\n" + "=" * 60)
        return False
        
    except Exception as e:
        print(f"❌ Unexpected error occurred!")
        print(f"\n🔴 Error: {type(e).__name__}")
        print(f"   {str(e)}")
        print("\n" + "=" * 60)
        return False

if __name__ == "__main__":
    success = test_connection()
    sys.exit(0 if success else 1)

