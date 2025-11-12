"""Database writer for match plugin results."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class MatchDatabaseWriter:
    """
    Write match plugin results to PostgreSQL database.

    This class handles:
    - Database connection management
    - Table creation/validation for topological_graph table
    - Clearing existing data before writing new data
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

    def clear_table_data(self) -> None:
        """
        Clear all data from the target table.

        This method truncates the table and resets the auto-increment sequence.
        If the table doesn't exist, this method does nothing.
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

        if not exists:
            logger.info(f"Table {self.full_table_name} does not exist, skipping clear operation")
            return

        logger.info(f"Clearing all data from table {self.full_table_name}...")

        # Truncate table and restart identity (reset auto-increment sequence)
        truncate_sql = f"TRUNCATE TABLE {self.full_table_name} RESTART IDENTITY;"
        self._cursor.execute(truncate_sql)

        self._conn.commit()
        logger.info(f"Table {self.full_table_name} cleared successfully")

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
        ttl: int | None = None,
        hops: int | None = None,
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
            ttl: TTL value (optional)
            hops: Network hops calculated from TTL (optional)
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

    def _determine_network_position(
        self,
        client_hops_a: int,
        server_hops_a: int,
        client_hops_b: int,
        server_hops_b: int,
    ) -> str:
        """
        Determine the relative network position of two capture points based on TTL deltas.

        This simplified method uses server-side TTL as the primary judgment criterion,
        with client-side TTL used only for consistency validation and logging.

        Args:
            client_hops_a: Number of hops from client to File A capture point
            server_hops_a: Number of hops from File A capture point to server
            client_hops_b: Number of hops from client to File B capture point
            server_hops_b: Number of hops from File B capture point to server

        Returns:
            One of the following position indicators:
            - "A_CLOSER_TO_CLIENT": File A is closer to client (Client -> A -> B -> Server)
            - "B_CLOSER_TO_CLIENT": File B is closer to client (Client -> B -> A -> Server)
            - "SAME_POSITION": Same position or cannot determine

        Logic:
            1. Calculate TTL delta differences:
               - client_delta_diff = client_hops_b - client_hops_a
               - server_delta_diff = server_hops_a - server_hops_b

            2. Detect NAT scenario (client and server deltas conflict)

            3. Always use server-side TTL for final judgment:
               - server_delta_diff > 0 → A_CLOSER_TO_CLIENT
               - server_delta_diff < 0 → B_CLOSER_TO_CLIENT
               - server_delta_diff == 0 → SAME_POSITION
        """
        # Calculate TTL delta differences
        client_delta_diff = client_hops_b - client_hops_a
        server_delta_diff = server_hops_a - server_hops_b

        # Detect potential NAT scenario (client and server deltas conflict)
        is_nat_scenario = (
            (client_delta_diff > 0 and server_delta_diff < 0) or
            (client_delta_diff < 0 and server_delta_diff > 0)
        )

        if is_nat_scenario:
            logger.debug(
                f"NAT scenario detected: client_delta={client_delta_diff}, "
                f"server_delta={server_delta_diff}. Using server-side TTL only."
            )

        # Always use server-side TTL for final judgment
        if server_delta_diff > 0:
            # A has more hops to server → A is farther from server → A closer to client
            return "A_CLOSER_TO_CLIENT"
        elif server_delta_diff < 0:
            # B has more hops to server → B is farther from server → B closer to client
            return "B_CLOSER_TO_CLIENT"
        else:
            # Same distance to server or cannot determine
            return "SAME_POSITION"

    def write_endpoint_stats(
        self,
        endpoint_stats: list,
        pcap_id_mapping: dict[str, int],
        file1_path: str,
        file2_path: str,
    ) -> int:
        """
        Write endpoint statistics to database.

        For each endpoint pair, creates nodes:
        - File A: Client node (type=1, no port) + Server node (type=2, with port)
        - File B: Client node (type=1, no port) + Server node (type=2, with port)
        - Network device nodes (type=1001/1002) when hops != 0:
          * type=1001: Network device between client and capture point
          * type=1002: Network device between capture point and server

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

        logger.info("Writing endpoint statistics to database...")
        logger.info(f"  File A pcap_id: {pcap_id_a}")
        logger.info(f"  File B pcap_id: {pcap_id_b}")

        records_inserted = 0

        # Process each endpoint pair
        for group_id, stat in enumerate(endpoint_stats, start=1):
            # Get protocol numbers from endpoint tuples
            proto_a = stat.tuple_a.protocol
            proto_b = stat.tuple_b.protocol

            # Determine network position based on TTL deltas
            position = self._determine_network_position(
                client_hops_a=stat.client_hops_a,
                server_hops_a=stat.server_hops_a,
                client_hops_b=stat.client_hops_b,
                server_hops_b=stat.server_hops_b,
            )

            # Debug logging for TTL-based topology detection
            logger.debug(
                f"TTL Topology Detection - Group {group_id}: "
                f"client_hops_a={stat.client_hops_a}, server_hops_a={stat.server_hops_a}, "
                f"client_hops_b={stat.client_hops_b}, server_hops_b={stat.server_hops_b}, "
                f"position={position}"
            )

            # Determine net_area for each node based on position
            # Constraint: Each pcap_id must have exactly ONE net_area marked (either client or server side)
            # to indicate the relative position between the two capture points.
            # The symmetric counterpart on the other pcap_id should also be marked.
            net_area_a_client = []
            net_area_a_server = []
            net_area_b_client = []
            net_area_b_server = []

            if position == "A_CLOSER_TO_CLIENT":
                # Client -> File A -> File B -> Server
                # File A (pcap_id=0): mark server side -> points to pcap_id_b
                # File B (pcap_id=1): mark client side -> points to pcap_id_a
                net_area_a_server = [pcap_id_b]
                net_area_b_client = [pcap_id_a]

            elif position == "B_CLOSER_TO_CLIENT":
                # Client -> File B -> File A -> Server
                # File B (pcap_id=1): mark server side -> points to pcap_id_a
                # File A (pcap_id=0): mark client side -> points to pcap_id_b
                net_area_b_server = [pcap_id_a]
                net_area_a_client = [pcap_id_b]

            # position == "SAME_POSITION": all net_area remain empty []

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
                net_area=net_area_a_client,
                stream_cnt=0,  # Client nodes always have stream_cnt=0
                pktlen=0,
                display_name="",
            )
            records_inserted += 1

            # File A - Network device between client and capture point (type=1001)
            # Only insert if client_hops_a > 0
            # Skip A-side client->capture device node when topology is Client->B->A->Server
            if stat.client_hops_a > 0 and position != "B_CLOSER_TO_CLIENT":
                self.insert_node(
                    pcap_id=pcap_id_a,
                    group_id=group_id,
                    ip=None,
                    port=None,
                    proto=None,
                    node_type=1001,  # Network device between client and capture point
                    is_capture=False,
                    net_area=[],
                    stream_cnt=0,
                    pktlen=0,
                    display_name=f"Network Device (Client-Capture, {stat.client_hops_a} hops)",
                )
                records_inserted += 1

            # File A - Server node (type=2, with port)
            # stream_cnt is set to stat.count for server nodes (type=2-5)
            # pktlen is set to total_bytes_a for server nodes (type=2-5)
            self.insert_node(
                pcap_id=pcap_id_a,
                group_id=group_id,
                ip=stat.tuple_a.server_ip,
                port=stat.tuple_a.server_port,
                proto=proto_a,  # Use actual protocol from connection
                node_type=2,  # Server type
                is_capture=False,
                net_area=net_area_a_server,
                stream_cnt=stat.count,  # Use count from endpoint pair
                pktlen=stat.total_bytes_a,  # Total bytes for this endpoint pair
                display_name="",
            )
            records_inserted += 1

            # File A - Network device between capture point and server (type=1002)
            # Only insert if server_hops_a > 0
            # Skip A-side capture->server device node when topology is Client->A->B->Server
            if stat.server_hops_a > 0 and position != "A_CLOSER_TO_CLIENT":
                self.insert_node(
                    pcap_id=pcap_id_a,
                    group_id=group_id,
                    ip=None,
                    port=None,
                    proto=None,
                    node_type=1002,  # Network device between capture point and server
                    is_capture=False,
                    net_area=[],
                    stream_cnt=0,
                    pktlen=0,
                    display_name=f"Network Device (Capture-Server, {stat.server_hops_a} hops)",
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
                net_area=net_area_b_client,
                stream_cnt=0,  # Client nodes always have stream_cnt=0
                pktlen=0,
                display_name="",
            )
            records_inserted += 1

            # File B - Network device between client and capture point (type=1001)
            # Only insert if client_hops_b > 0
            # Skip B-side client->capture device node when topology is Client->A->B->Server
            if stat.client_hops_b > 0 and position != "A_CLOSER_TO_CLIENT":
                self.insert_node(
                    pcap_id=pcap_id_b,
                    group_id=group_id,
                    ip=None,
                    port=None,
                    proto=None,
                    node_type=1001,  # Network device between client and capture point
                    is_capture=False,
                    net_area=[],
                    stream_cnt=0,
                    pktlen=0,
                    display_name=f"Network Device (Client-Capture, {stat.client_hops_b} hops)",
                )
                records_inserted += 1

            # File B - Server node (type=2, with port)
            # stream_cnt is set to stat.count for server nodes (type=2-5)
            # pktlen is set to total_bytes_b for server nodes (type=2-5)
            self.insert_node(
                pcap_id=pcap_id_b,
                group_id=group_id,
                ip=stat.tuple_b.server_ip,
                port=stat.tuple_b.server_port,
                proto=proto_b,  # Use actual protocol from connection
                node_type=2,  # Server type
                is_capture=False,
                net_area=net_area_b_server,
                stream_cnt=stat.count,  # Use count from endpoint pair
                pktlen=stat.total_bytes_b,  # Total bytes for this endpoint pair
                display_name="",
            )
            records_inserted += 1

            # File B - Network device between capture point and server (type=1002)
            # Only insert if server_hops_b > 0
            # Skip B-side capture->server device node when topology is Client->B->A->Server
            if stat.server_hops_b > 0 and position != "B_CLOSER_TO_CLIENT":
                self.insert_node(
                    pcap_id=pcap_id_b,
                    group_id=group_id,
                    ip=None,
                    port=None,
                    proto=None,
                    node_type=1002,  # Network device between capture point and server
                    is_capture=False,
                    net_area=[],
                    stream_cnt=0,
                    pktlen=0,
                    display_name=f"Network Device (Capture-Server, {stat.server_hops_b} hops)",
                )
                records_inserted += 1

            # Format protocol name for logging
            proto_name_a = "TCP" if proto_a == 6 else "UDP" if proto_a == 17 else f"Proto{proto_a}"
            proto_name_b = "TCP" if proto_b == 6 else "UDP" if proto_b == 17 else f"Proto{proto_b}"

            # Build network device info for logging
            net_devices_a = []
            if stat.client_hops_a > 0:
                net_devices_a.append(f"Client-Capture:{stat.client_hops_a}h")
            if stat.server_hops_a > 0:
                net_devices_a.append(f"Capture-Server:{stat.server_hops_a}h")

            net_devices_b = []
            if stat.client_hops_b > 0:
                net_devices_b.append(f"Client-Capture:{stat.client_hops_b}h")
            if stat.server_hops_b > 0:
                net_devices_b.append(f"Capture-Server:{stat.server_hops_b}h")

            net_info_a = f" +{','.join(net_devices_a)}" if net_devices_a else ""
            net_info_b = f" +{','.join(net_devices_b)}" if net_devices_b else ""

            # Format position description for logging
            position_desc = {
                "A_CLOSER_TO_CLIENT": "Client→A→B→Server",
                "B_CLOSER_TO_CLIENT": "Client→B→A→Server",
                "A_CLOSER_TO_SERVER": "A closer to Server",
                "B_CLOSER_TO_SERVER": "B closer to Server",
                "SAME_POSITION": "Same position/Unknown",
            }.get(position, position)

            logger.info(
                f"  Group {group_id} (count={stat.count}, proto={proto_name_a}/{proto_name_b}, position={position_desc}): "
                f"A({stat.tuple_a.client_ip} → {stat.tuple_a.server_ip}:{stat.tuple_a.server_port}{net_info_a}) | "
                f"B({stat.tuple_b.client_ip} → {stat.tuple_b.server_ip}:{stat.tuple_b.server_port}{net_info_b})"
            )

        return records_inserted

    @staticmethod
    def write_endpoint_stats_to_json(
        endpoint_stats: list,
        pcap_id_mapping: dict[str, int],
        file1_path: str,
        file2_path: str,
        output_file: Path,
    ) -> int:
        """
        Write endpoint statistics to JSON file.

        This method generates the same data structure as write_endpoint_stats,
        but outputs it as JSON lines (one JSON object per line) instead of
        writing to database.

        Args:
            endpoint_stats: List of EndpointPairStats objects
            pcap_id_mapping: Mapping from file path to pcap_id
            file1_path: Path to file A (as string)
            file2_path: Path to file B (as string)
            output_file: Path to output JSON file

        Returns:
            Number of records written
        """
        # Get pcap_ids for both files
        pcap_id_a = pcap_id_mapping.get(file1_path, 0)
        pcap_id_b = pcap_id_mapping.get(file2_path, 1)

        logger.info(f"Writing endpoint statistics to JSON file: {output_file}")
        logger.info(f"  File A pcap_id: {pcap_id_a}")
        logger.info(f"  File B pcap_id: {pcap_id_b}")

        records = []
        records_count = 0

        # Process each endpoint pair
        for group_id, stat in enumerate(endpoint_stats, start=1):
            # Get protocol numbers from endpoint tuples
            proto_a = stat.tuple_a.protocol
            proto_b = stat.tuple_b.protocol

            # Determine network position based on TTL deltas
            position = MatchDatabaseWriter._determine_network_position_static(
                client_hops_a=stat.client_hops_a,
                server_hops_a=stat.server_hops_a,
                client_hops_b=stat.client_hops_b,
                server_hops_b=stat.server_hops_b,
            )

            # Determine net_area for each node based on position
            net_area_a_client = []
            net_area_a_server = []
            net_area_b_client = []
            net_area_b_server = []

            if position == "A_CLOSER_TO_CLIENT":
                net_area_a_server = [pcap_id_b]
                net_area_b_client = [pcap_id_a]
            elif position == "B_CLOSER_TO_CLIENT":
                net_area_b_server = [pcap_id_a]
                net_area_a_client = [pcap_id_b]
            elif position == "A_CLOSER_TO_SERVER":
                net_area_b_client = [pcap_id_a]
            elif position == "B_CLOSER_TO_SERVER":
                net_area_a_client = [pcap_id_b]

            # File A - Client node (type=1, no port)
            records.append({
                "pcap_id": pcap_id_a,
                "group_id": group_id,
                "type": 1,
                "is_capture": False,
                "net_area": net_area_a_client,
                "stream_cnt": 0,
                "pktlen": 0,
                "display_name": "",
                "metrics": {"stream_cnt": 0},
                "ip": stat.tuple_a.client_ip,
            })
            records_count += 1

            # File A - Network device between client and capture point (type=1001)
            if stat.client_hops_a > 0 and position != "B_CLOSER_TO_CLIENT":
                records.append({
                    "pcap_id": pcap_id_a,
                    "group_id": group_id,
                    "type": 1001,
                    "is_capture": False,
                    "net_area": [],
                    "stream_cnt": 0,
                    "pktlen": 0,
                    "display_name": "",
                    "metrics": {"stream_cnt": 0},
                })
                records_count += 1

            # File A - Server node (type=2, with port)
            records.append({
                "pcap_id": pcap_id_a,
                "group_id": group_id,
                "ip": stat.tuple_a.server_ip,
                "port": stat.tuple_a.server_port,
                "proto": proto_a,
                "type": 2,
                "is_capture": False,
                "net_area": net_area_a_server,
                "stream_cnt": stat.count,
                "pktlen": stat.total_bytes_a,
                "display_name": "",
                "metrics": {"stream_cnt": stat.count},
            })
            records_count += 1

            # File A - Network device between capture point and server (type=1002)
            if stat.server_hops_a > 0 and position != "A_CLOSER_TO_CLIENT":
                records.append({
                    "pcap_id": pcap_id_a,
                    "group_id": group_id,
                    "type": 1002,
                    "is_capture": False,
                    "net_area": [],
                    "stream_cnt": 0,
                    "pktlen": 0,
                    "display_name": "",
                    "metrics": {"stream_cnt": 0},
                })
                records_count += 1

            # File B - Client node (type=1, no port)
            records.append({
                "pcap_id": pcap_id_b,
                "group_id": group_id,
                "type": 1,
                "is_capture": False,
                "net_area": net_area_b_client,
                "stream_cnt": 0,
                "pktlen": 0,
                "display_name": "",
                "metrics": {"stream_cnt": 0},
                "ip": stat.tuple_b.client_ip,
            })
            records_count += 1

            # File B - Network device between client and capture point (type=1001)
            if stat.client_hops_b > 0 and position != "A_CLOSER_TO_CLIENT":
                records.append({
                    "pcap_id": pcap_id_b,
                    "group_id": group_id,
                    "type": 1001,
                    "is_capture": False,
                    "net_area": [],
                    "stream_cnt": 0,
                    "pktlen": 0,
                    "display_name": "",
                    "metrics": {"stream_cnt": 0},
                })
                records_count += 1

            # File B - Server node (type=2, with port)
            records.append({
                "pcap_id": pcap_id_b,
                "group_id": group_id,
                "ip": stat.tuple_b.server_ip,
                "port": stat.tuple_b.server_port,
                "proto": proto_b,
                "type": 2,
                "is_capture": False,
                "net_area": net_area_b_server,
                "stream_cnt": stat.count,
                "pktlen": stat.total_bytes_b,
                "display_name": "",
                "metrics": {"stream_cnt": stat.count},
            })
            records_count += 1

            # File B - Network device between capture point and server (type=1002)
            if stat.server_hops_b > 0 and position != "B_CLOSER_TO_CLIENT":
                records.append({
                    "pcap_id": pcap_id_b,
                    "group_id": group_id,
                    "type": 1002,
                    "is_capture": False,
                    "net_area": [],
                    "stream_cnt": 0,
                    "pktlen": 0,
                    "display_name": "",
                    "metrics": {"stream_cnt": 0},
                })
                records_count += 1

        # Create parent directory if it doesn't exist
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write to file (one JSON object per line)
        with open(output_file, 'w', encoding='utf-8') as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False) + '\n')

        logger.info(f"Successfully wrote {records_count} records to {output_file}")
        return records_count

    @staticmethod
    def _determine_network_position_static(
        client_hops_a: int,
        server_hops_a: int,
        client_hops_b: int,
        server_hops_b: int,
    ) -> str:
        """
        Static version of _determine_network_position for use in static methods.

        This simplified method uses server-side TTL as the primary judgment criterion,
        with client-side TTL used only for consistency validation and logging.

        Args:
            client_hops_a: Number of hops from client to File A capture point
            server_hops_a: Number of hops from File A capture point to server
            client_hops_b: Number of hops from client to File B capture point
            server_hops_b: Number of hops from File B capture point to server

        Returns:
            Position indicator string:
            - "A_CLOSER_TO_CLIENT": A is farther from server
            - "B_CLOSER_TO_CLIENT": B is farther from server
            - "SAME_POSITION": Same distance or cannot determine
        """
        # Calculate TTL delta differences
        client_delta_diff = client_hops_b - client_hops_a
        server_delta_diff = server_hops_a - server_hops_b

        # Detect potential NAT scenario (client and server deltas conflict)
        is_nat_scenario = (
            (client_delta_diff > 0 and server_delta_diff < 0) or
            (client_delta_diff < 0 and server_delta_diff > 0)
        )

        if is_nat_scenario:
            logger.debug(
                f"NAT scenario detected: client_delta={client_delta_diff}, "
                f"server_delta={server_delta_diff}. Using server-side TTL only."
            )

        # Always use server-side TTL for final judgment
        if server_delta_diff > 0:
            # A has more hops to server → A is farther from server → A closer to client
            return "A_CLOSER_TO_CLIENT"
        elif server_delta_diff < 0:
            # B has more hops to server → B is farther from server → B closer to client
            return "B_CLOSER_TO_CLIENT"
        else:
            # Same distance to server or cannot determine
            return "SAME_POSITION"

