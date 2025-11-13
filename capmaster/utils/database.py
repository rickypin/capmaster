"""Base database writer with common connection management."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class BaseDatabaseWriter(ABC):
    """
    Base class for database writers with common connection management.
    
    This class provides:
    - Database connection management (connect, close, context manager)
    - Common table operations (check existence, create sequence, etc.)
    - Transaction management (commit, rollback)
    
    Subclasses must implement:
    - ensure_table_exists(): Define table schema and creation logic
    """
    
    def __init__(self, connection_string: str, kase_id: int, table_suffix: str):
        """
        Initialize database writer.
        
        Args:
            connection_string: PostgreSQL connection string (e.g., "postgresql://user:pass@host:port/db")
            kase_id: Case ID for table name construction
            table_suffix: Table name suffix (e.g., "topological_graph" -> kase_137_topological_graph)
        """
        self.connection_string = connection_string
        self.kase_id = kase_id
        self.table_name = f"kase_{kase_id}_{table_suffix}"
        self.full_table_name = f"public.{self.table_name}"
        self._conn = None
        self._cursor = None
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
    
    def connect(self) -> None:
        """
        Establish database connection.
        
        Raises:
            ImportError: If psycopg2 is not installed
            Exception: If connection fails
        """
        try:
            import psycopg2
        except ImportError:
            raise ImportError(
                "Database functionality requires psycopg2-binary.\n"
                "Install with one of the following methods:\n"
                "  1. pip install capmaster[database]\n"
                "  2. pip install -r requirements-database.txt\n"
                "  3. pip install psycopg2-binary"
            )
        
        # Parse connection string
        parsed = urlparse(self.connection_string)
        
        try:
            self._conn = psycopg2.connect(
                host=parsed.hostname,
                port=parsed.port or 5432,
                database=parsed.path.lstrip('/'),
                user=parsed.username,
                password=parsed.password,
                connect_timeout=10
            )
            self._conn.autocommit = False  # Use transactions
            self._cursor = self._conn.cursor()
            logger.info(f"Connected to database: {parsed.hostname}:{parsed.port}/{parsed.path.lstrip('/')}")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise
    
    def close(self) -> None:
        """Close database connection."""
        if self._cursor:
            self._cursor.close()
        if self._conn:
            self._conn.close()
        logger.info("Database connection closed")
    
    def commit(self) -> None:
        """Commit current transaction."""
        if self._conn:
            self._conn.commit()
            logger.info("Transaction committed")
    
    def rollback(self) -> None:
        """Rollback current transaction."""
        if self._conn:
            self._conn.rollback()
            logger.warning("Transaction rolled back")
    
    def _check_table_exists(self) -> bool:
        """
        Check if the target table exists.
        
        Returns:
            True if table exists, False otherwise
        """
        if not self._cursor or not self._conn:
            raise RuntimeError("Database not connected")
        
        self._cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = %s
            );
        """, (self.table_name,))
        
        return self._cursor.fetchone()[0]
    
    def _create_sequence_and_primary_key(self) -> None:
        """
        Create sequence for id column and set up primary key.
        
        This is a common pattern for auto-increment id columns.
        Should be called after table creation.
        """
        if not self._cursor or not self._conn:
            raise RuntimeError("Database not connected")
        
        # Create sequence for id column
        sequence_name = f"{self.table_name}_id_seq"
        create_sequence_sql = f"""
            CREATE SEQUENCE public.{sequence_name}
                START WITH 1
                INCREMENT BY 1
                NO MINVALUE
                NO MAXVALUE
                CACHE 1;
        """
        
        self._cursor.execute(create_sequence_sql)

        # Set sequence ownership
        self._cursor.execute(f"""
            ALTER SEQUENCE public.{sequence_name} OWNED BY {self.full_table_name}.id;
        """)

        # Set default value for id column
        self._cursor.execute(f"""
            ALTER TABLE ONLY {self.full_table_name}
            ALTER COLUMN id SET DEFAULT nextval('public.{sequence_name}'::regclass);
        """)

        # Add primary key constraint
        self._cursor.execute(f"""
            ALTER TABLE ONLY {self.full_table_name}
            ADD CONSTRAINT {self.table_name}_pkey PRIMARY KEY (id);
        """)

    @abstractmethod
    def ensure_table_exists(self) -> None:
        """
        Ensure the target table exists, create it if not.

        Subclasses must implement this method to define their specific table schema.
        """
        pass

