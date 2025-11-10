"""Database writer for match plugin results."""

from __future__ import annotations
import logging
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class MatchDatabaseWriter:
    """
    Write match plugin results to PostgreSQL database.
    
    This class handles:
    - Database connection management
    - Table creation/validation for topological_graph table
    - Data insertion for matched connection results
    """
    
    def __init__(self, connection_string: str, kase_id: int):
        """
        Initialize database writer.
        
        Args:
            connection_string: PostgreSQL connection string (e.g., "postgresql://user:pass@host:port/db")
            kase_id: Case ID for table name construction (e.g., 137 -> kase_137_topological_graph)
        """
        self.connection_string = connection_string
        self.kase_id = kase_id
        self.table_name = f"kase_{kase_id}_topological_graph"
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

        The table schema for topological_graph:
        - pcap_id: integer (PCAP file identifier)
        - group_id: integer (group identifier)
        - ip: varchar (IP address)
        - port: integer (port number)
        - proto: integer (protocol number, e.g., 6 for TCP)
        - type: integer (node type)
        - is_capture: boolean (whether this is a capture point)
        - net_area: array (network area identifiers)
        - stream_cnt: bigint (stream count)
        - pktlen: bigint (packet length total)
        - display_name: varchar (display name)
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
            return

        logger.info(f"Creating table {self.full_table_name}...")

        # Create table with schema matching reference table
        create_table_sql = f"""
            CREATE TABLE {self.full_table_name} (
                pcap_id integer,
                group_id integer,
                ip varchar,
                port integer,
                proto integer,
                type integer,
                is_capture boolean,
                net_area integer[],
                stream_cnt bigint,
                pktlen bigint,
                display_name varchar,
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

        self._conn.commit()
        logger.info(f"Table {self.full_table_name} created successfully")

    def insert_node(
        self,
        pcap_id: int,
        group_id: int,
        ip: str | None = None,
        port: int | None = None,
        proto: int | None = None,
        node_type: int = 1,
        is_capture: bool = False,
        net_area: list[int] | None = None,
        stream_cnt: int = 0,
        pktlen: int = 0,
        display_name: str = "",
    ) -> None:
        """
        Insert a topological graph node record into the database.

        Args:
            pcap_id: PCAP file identifier (0 or 1)
            group_id: Group identifier for this node
            ip: IP address (optional)
            port: Port number (optional)
            proto: Protocol number (e.g., 6 for TCP, optional)
            node_type: Node type identifier (default: 1)
            is_capture: Whether this is a capture point (default: False)
            net_area: List of network area identifiers (default: empty list)
            stream_cnt: Stream count (default: 0)
            pktlen: Total packet length (default: 0)
            display_name: Display name for the node (default: empty string)
        """
        if not self._cursor or not self._conn:
            raise RuntimeError("Database not connected")

        # Default values
        if net_area is None:
            net_area = []

        insert_sql = f"""
            INSERT INTO {self.full_table_name} (
                pcap_id,
                group_id,
                ip,
                port,
                proto,
                type,
                is_capture,
                net_area,
                stream_cnt,
                pktlen,
                display_name
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        self._cursor.execute(
            insert_sql,
            (
                pcap_id,
                group_id,
                ip,
                port,
                proto,
                node_type,
                is_capture,
                net_area,
                stream_cnt,
                pktlen,
                display_name,
            )
        )
        
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

    def write_endpoint_stats(
        self,
        endpoint_stats: list,
        pcap_id_mapping: dict[str, int],
        file1_path: str,
        file2_path: str,
    ) -> int:
        """
        Write endpoint statistics to database.

        For each endpoint pair, creates 4 nodes:
        - File A: Client node (type=1, no port) + Server node (type=2, with port)
        - File B: Client node (type=1, no port) + Server node (type=2, with port)

        Args:
            endpoint_stats: List of EndpointPairStats objects
            pcap_id_mapping: Mapping from file path to pcap_id
            file1_path: Path to file A (as string)
            file2_path: Path to file B (as string)

        Returns:
            Number of records inserted
        """
        if not self._cursor or not self._conn:
            raise RuntimeError("Database not connected")

        # Get pcap_ids for both files
        pcap_id_a = pcap_id_mapping.get(file1_path, 0)
        pcap_id_b = pcap_id_mapping.get(file2_path, 1)

        logger.info(f"Writing endpoint statistics to database...")
        logger.info(f"  File A pcap_id: {pcap_id_a}")
        logger.info(f"  File B pcap_id: {pcap_id_b}")

        records_inserted = 0

        # Process each endpoint pair
        for group_id, stat in enumerate(endpoint_stats, start=1):
            # Get protocol numbers from endpoint tuples
            proto_a = stat.tuple_a.protocol
            proto_b = stat.tuple_b.protocol

            # File A - Client node (type=1, no port)
            # stream_cnt is 0 for client nodes (type=1)
            self.insert_node(
                pcap_id=pcap_id_a,
                group_id=group_id,
                ip=stat.tuple_a.client_ip,
                port=None,
                proto=None,
                node_type=1,  # Client type
                is_capture=False,
                net_area=[],
                stream_cnt=0,  # Client nodes always have stream_cnt=0
                pktlen=0,
                display_name="",
            )
            records_inserted += 1

            # File A - Server node (type=2, with port)
            # stream_cnt is set to stat.count for server nodes (type=2-5)
            self.insert_node(
                pcap_id=pcap_id_a,
                group_id=group_id,
                ip=stat.tuple_a.server_ip,
                port=stat.tuple_a.server_port,
                proto=proto_a,  # Use actual protocol from connection
                node_type=2,  # Server type
                is_capture=False,
                net_area=[],
                stream_cnt=stat.count,  # Use count from endpoint pair
                pktlen=0,
                display_name="",
            )
            records_inserted += 1

            # File B - Client node (type=1, no port)
            # stream_cnt is 0 for client nodes (type=1)
            self.insert_node(
                pcap_id=pcap_id_b,
                group_id=group_id,
                ip=stat.tuple_b.client_ip,
                port=None,
                proto=None,
                node_type=1,  # Client type
                is_capture=False,
                net_area=[],
                stream_cnt=0,  # Client nodes always have stream_cnt=0
                pktlen=0,
                display_name="",
            )
            records_inserted += 1

            # File B - Server node (type=2, with port)
            # stream_cnt is set to stat.count for server nodes (type=2-5)
            self.insert_node(
                pcap_id=pcap_id_b,
                group_id=group_id,
                ip=stat.tuple_b.server_ip,
                port=stat.tuple_b.server_port,
                proto=proto_b,  # Use actual protocol from connection
                node_type=2,  # Server type
                is_capture=False,
                net_area=[],
                stream_cnt=stat.count,  # Use count from endpoint pair
                pktlen=0,
                display_name="",
            )
            records_inserted += 1

            # Format protocol name for logging
            proto_name_a = "TCP" if proto_a == 6 else "UDP" if proto_a == 17 else f"Proto{proto_a}"
            proto_name_b = "TCP" if proto_b == 6 else "UDP" if proto_b == 17 else f"Proto{proto_b}"

            logger.info(
                f"  Group {group_id} (count={stat.count}, proto={proto_name_a}/{proto_name_b}): "
                f"A({stat.tuple_a.client_ip} → {stat.tuple_a.server_ip}:{stat.tuple_a.server_port}) | "
                f"B({stat.tuple_b.client_ip} → {stat.tuple_b.server_ip}:{stat.tuple_b.server_port})"
            )

        return records_inserted

