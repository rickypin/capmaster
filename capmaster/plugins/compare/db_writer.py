"""Database writer for compare plugin results."""

from __future__ import annotations
import logging
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class DatabaseWriter:
    """
    Write compare plugin results to PostgreSQL database.
    
    This class handles:
    - Database connection management
    - Table creation based on reference schema
    - Data insertion for flow hash and comparison results
    """
    
    def __init__(self, connection_string: str, kase_id: int):
        """
        Initialize database writer.
        
        Args:
            connection_string: PostgreSQL connection string (e.g., "postgresql://user:pass@host:port/db")
            kase_id: Case ID for table name construction (e.g., 133 -> kase_133_tcp_stream_extra)
        """
        self.connection_string = connection_string
        self.kase_id = kase_id
        self.table_name = f"kase_{kase_id}_tcp_stream_extra"
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
        
    def ensure_table_exists(self) -> None:
        """
        Ensure the target table exists, create it if not.

        The table schema is based on the reference table structure:
        - pcap_id: integer
        - flow_hash: bigint
        - first_time: bigint (nanosecond timestamp)
        - last_time: bigint (nanosecond timestamp)
        - tcp_flags_different_cnt: bigint
        - tcp_flags_different_type: text (e.g., "SYN (Local Side) -> ACK" or "SYN -> ACK (Local Side)")
        - tcp_flags_different_text: text (string, semicolon-separated)
        - seq_num_different_cnt: bigint
        - seq_num_different_text: text (string, semicolon-separated)
        - id: integer (primary key, auto-increment)
        """
        if not self._cursor or not self._conn:
            raise RuntimeError("Database not connected")

        # Check if table exists
        self._cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = %s
            );
        """, (self.table_name,))

        exists = self._cursor.fetchone()[0]

        if exists:
            logger.info(f"Table {self.full_table_name} already exists")
            # Check if tcp_flags_different_type column exists, add it if not
            self._cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.columns
                    WHERE table_schema = 'public'
                    AND table_name = %s
                    AND column_name = 'tcp_flags_different_type'
                );
            """, (self.table_name,))

            has_type_column = self._cursor.fetchone()[0]

            if not has_type_column:
                logger.info(f"Adding tcp_flags_different_type column to {self.full_table_name}...")
                # Add the column after tcp_flags_different_cnt
                self._cursor.execute(f"""
                    ALTER TABLE {self.full_table_name}
                    ADD COLUMN tcp_flags_different_type text;
                """)
                self._conn.commit()
                logger.info(f"Column tcp_flags_different_type added successfully")
            return

        logger.info(f"Creating table {self.full_table_name}...")

        # Create table with schema matching reference table
        create_table_sql = f"""
            CREATE TABLE {self.full_table_name} (
                pcap_id integer,
                flow_hash bigint,
                first_time bigint,
                last_time bigint,
                tcp_flags_different_cnt bigint,
                tcp_flags_different_type text,
                tcp_flags_different_text text,
                seq_num_different_cnt bigint,
                seq_num_different_text text,
                id integer NOT NULL
            );
        """

        self._cursor.execute(create_table_sql)
        
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
        
        # Create indexes for better query performance
        self._cursor.execute(f"""
            CREATE INDEX idx_{self.table_name}_flow_hash
            ON {self.full_table_name} USING btree (flow_hash);
        """)

        self._cursor.execute(f"""
            CREATE INDEX idx_{self.table_name}_pcap_id
            ON {self.full_table_name} USING btree (pcap_id);
        """)

        self._cursor.execute(f"""
            CREATE INDEX idx_{self.table_name}_time
            ON {self.full_table_name} USING btree (first_time, last_time);
        """)

        self._conn.commit()
        logger.info(f"Table {self.full_table_name} created successfully")

    def insert_flow_hash(
        self,
        pcap_id: int,
        flow_hash: int,
        first_time: int | None = None,
        last_time: int | None = None,
        tcp_flags_different_cnt: int = 0,
        tcp_flags_different_type: str | None = None,
        tcp_flags_different_text: list[str] | None = None,
        seq_num_different_cnt: int = 0,
        seq_num_different_text: list[str] | None = None,
    ) -> None:
        """
        Insert a flow hash record into the database.

        Args:
            pcap_id: PCAP file identifier
            flow_hash: Flow hash value (signed 64-bit integer)
            first_time: First packet timestamp in nanoseconds (optional)
            last_time: Last packet timestamp in nanoseconds (optional)
            tcp_flags_different_cnt: Count of TCP flags differences
            tcp_flags_different_type: TCP flags change type (e.g., "SYN (Local Side) -> ACK" or "SYN -> ACK (Local Side)")
            tcp_flags_different_text: String of TCP flags difference descriptions (semicolon-separated)
            seq_num_different_cnt: Count of sequence number differences
            seq_num_different_text: String of sequence number difference descriptions (semicolon-separated)
        """
        if not self._cursor or not self._conn:
            raise RuntimeError("Database not connected")

        # Convert None to empty string for text fields
        if tcp_flags_different_text is None:
            tcp_flags_different_text = ""
        if seq_num_different_text is None:
            seq_num_different_text = ""

        insert_sql = f"""
            INSERT INTO {self.full_table_name} (
                pcap_id,
                flow_hash,
                first_time,
                last_time,
                tcp_flags_different_cnt,
                tcp_flags_different_type,
                tcp_flags_different_text,
                seq_num_different_cnt,
                seq_num_different_text
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        self._cursor.execute(
            insert_sql,
            (
                pcap_id,
                flow_hash,
                first_time,
                last_time,
                tcp_flags_different_cnt,
                tcp_flags_different_type,
                tcp_flags_different_text,
                seq_num_different_cnt,
                seq_num_different_text,
            )
        )

    def insert_flow_hash_batch(
        self,
        records: list[dict],
    ) -> None:
        """
        Insert multiple flow hash records into the database in a single batch operation.

        OPTIMIZATION: This method reduces database round-trips from N (one per record)
        to 1 (single batch insert), significantly improving performance when writing
        large numbers of records.

        Args:
            records: List of dictionaries, each containing:
                - pcap_id: PCAP file identifier
                - flow_hash: Flow hash value (signed 64-bit integer)
                - first_time: First packet timestamp in nanoseconds (optional)
                - last_time: Last packet timestamp in nanoseconds (optional)
                - tcp_flags_different_cnt: Count of TCP flags differences
                - tcp_flags_different_type: TCP flags change type (optional)
                - tcp_flags_different_text: TCP flags difference descriptions (optional)
                - seq_num_different_cnt: Count of sequence number differences
                - seq_num_different_text: Sequence number difference descriptions (optional)
        """
        if not self._cursor or not self._conn:
            raise RuntimeError("Database not connected")

        if not records:
            return

        # Build batch insert SQL
        insert_sql = f"""
            INSERT INTO {self.full_table_name} (
                pcap_id,
                flow_hash,
                first_time,
                last_time,
                tcp_flags_different_cnt,
                tcp_flags_different_type,
                tcp_flags_different_text,
                seq_num_different_cnt,
                seq_num_different_text
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        # Prepare batch data
        batch_data = []
        for record in records:
            # Convert None to empty string for text fields
            tcp_flags_text = record.get('tcp_flags_different_text', '')
            if tcp_flags_text is None:
                tcp_flags_text = ''

            seq_num_text = record.get('seq_num_different_text', '')
            if seq_num_text is None:
                seq_num_text = ''

            batch_data.append((
                record['pcap_id'],
                record['flow_hash'],
                record.get('first_time'),
                record.get('last_time'),
                record.get('tcp_flags_different_cnt', 0),
                record.get('tcp_flags_different_type'),
                tcp_flags_text,
                record.get('seq_num_different_cnt', 0),
                seq_num_text,
            ))

        # Execute batch insert using executemany
        self._cursor.executemany(insert_sql, batch_data)

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

