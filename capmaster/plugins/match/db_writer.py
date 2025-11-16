"""Database writer for match plugin results."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from capmaster.plugins.match.endpoint_stats import EndpointPairStats, ServiceStats
from capmaster.utils.database import BaseDatabaseWriter

logger = logging.getLogger(__name__)


class MatchDatabaseWriter(BaseDatabaseWriter):
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
        super().__init__(connection_string, kase_id, "topological_graph")

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

        # Check if table exists using base class method
        if self._check_table_exists():
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

        # Create sequence and primary key using base class method
        self._create_sequence_and_primary_key()

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

        # Check if table exists using base class method
        if not self._check_table_exists():
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
            ),
        )

    def _determine_network_position(
        self,
        client_hops_a: int,
        server_hops_a: int,
        client_hops_b: int,
        server_hops_b: int,
        client_ttl_a: int = 0,
        server_ttl_a: int = 0,
        client_ttl_b: int = 0,
        server_ttl_b: int = 0,
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
            client_ttl_a: Original client TTL value from file A (optional)
            server_ttl_a: Original server TTL value from file A (optional)
            client_ttl_b: Original client TTL value from file B (optional)
            server_ttl_b: Original server TTL value from file B (optional)

        Returns:
            One of the following position indicators:
            - "A_CLOSER_TO_CLIENT": File A is closer to client (Client -> A -> B -> Server)
            - "B_CLOSER_TO_CLIENT": File B is closer to client (Client -> B -> A -> Server)
            - "A_CLOSER_TO_SERVER": File A is closer to server (Client -> B -> A -> Server)
            - "B_CLOSER_TO_SERVER": File B is closer to server (Client -> A -> B -> Server)
            - "SAME_POSITION": Same position or cannot determine

        Logic:
            1. Check for original TTL values (255, 128, 64):
               - These values indicate network devices (routers, load balancers)
               - If one point sees original client TTL and another sees original server TTL:
                 * Point seeing client=255 → closer to SERVER (device on client side)
                 * Point seeing server=255 → closer to CLIENT (device on server side)
               - Example: Client → [Device TTL=255] → B → A → Server
                 * A sees client=255 → A closer to server → B_CLOSER_TO_CLIENT

            2. Calculate TTL delta differences:
               - client_delta_diff = client_hops_b - client_hops_a
               - server_delta_diff = server_hops_a - server_hops_b

            3. Detect NAT scenario (client and server deltas conflict)

            4. Always use server-side TTL for final judgment:
               - server_delta_diff > 0 → A_CLOSER_TO_CLIENT
               - server_delta_diff < 0 → B_CLOSER_TO_CLIENT
               - server_delta_diff == 0 → SAME_POSITION
        """
        # Check for original TTL values (common initial TTL values: 255, 128, 64)
        ORIGINAL_TTL_VALUES = {255, 128, 64}

        # Check if we have original TTL scenario
        client_a_is_original = client_ttl_a in ORIGINAL_TTL_VALUES
        server_a_is_original = server_ttl_a in ORIGINAL_TTL_VALUES
        client_b_is_original = client_ttl_b in ORIGINAL_TTL_VALUES
        server_b_is_original = server_ttl_b in ORIGINAL_TTL_VALUES

        # Special case: If one file has original client TTL and another has original server TTL
        # This indicates the capture points are on opposite sides of the connection
        # Rule: The point seeing original client TTL is closer to SERVER
        #       The point seeing original server TTL is closer to CLIENT
        if (
            client_a_is_original
            and server_b_is_original
            and not server_a_is_original
            and not client_b_is_original
        ):
            # A sees original client TTL, B sees original server TTL
            # → A is closer to server, B is closer to client
            logger.debug(
                f"Original TTL detected: client_ttl_a={client_ttl_a} (original), "
                f"server_ttl_b={server_ttl_b} (original). B is closer to client."
            )
            return "B_CLOSER_TO_CLIENT"

        if (
            server_a_is_original
            and client_b_is_original
            and not client_a_is_original
            and not server_b_is_original
        ):
            # A sees original server TTL, B sees original client TTL
            # → A is closer to client, B is closer to server
            logger.debug(
                f"Original TTL detected: server_ttl_a={server_ttl_a} (original), "
                f"client_ttl_b={client_ttl_b} (original). A is closer to client."
            )
            return "A_CLOSER_TO_CLIENT"

        if (
            client_b_is_original
            and server_a_is_original
            and not server_b_is_original
            and not client_a_is_original
        ):
            # B sees original client TTL, A sees original server TTL
            # → B is closer to server, A is closer to client
            logger.debug(
                f"Original TTL detected: client_ttl_b={client_ttl_b} (original), "
                f"server_ttl_a={server_ttl_a} (original). A is closer to client."
            )
            return "A_CLOSER_TO_CLIENT"

        if (
            server_b_is_original
            and client_a_is_original
            and not client_b_is_original
            and not server_a_is_original
        ):
            # B sees original server TTL, A sees original client TTL
            # → B is closer to client, A is closer to server
            logger.debug(
                f"Original TTL detected: server_ttl_b={server_ttl_b} (original), "
                f"client_ttl_a={client_ttl_a} (original). B is closer to client."
            )
            return "B_CLOSER_TO_CLIENT"

        # Calculate TTL delta differences
        client_delta_diff = client_hops_b - client_hops_a
        server_delta_diff = server_hops_a - server_hops_b

        # Detect potential NAT scenario (client and server deltas conflict)
        is_nat_scenario = (client_delta_diff > 0 and server_delta_diff < 0) or (
            client_delta_diff < 0 and server_delta_diff > 0
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

        # Process each endpoint pair using unified data generation
        for group_id, stat in enumerate(endpoint_stats, start=1):
            # Generate unified node data
            nodes = self._generate_endpoint_pair_nodes(
                group_id=group_id,
                stat=stat,
                pcap_id_a=pcap_id_a,
                pcap_id_b=pcap_id_b,
            )

            # Insert each node into database
            for node in nodes:
                self.insert_node(**node)
                records_inserted += 1

        return records_inserted

    def write_service_stats(
        self,
        service_stats: list,  # list[ServiceStats]
        pcap_id_mapping: dict[str, int],
        file1_path: str,
        file2_path: str,
        service_to_group_mapping: dict | None = None,  # dict[ServiceKey, int]
    ) -> int:
        """
        Write service statistics to database.

        Each service gets one group_id. All unique client IPs and server IPs
        within the service are written as separate nodes, but without preserving
        the client-server pairing relationship.

        Args:
            service_stats: List of ServiceStats objects
            pcap_id_mapping: Mapping from file path to pcap_id
            file1_path: Path to file A (as string)
            file2_path: Path to file B (as string)
            service_to_group_mapping: Optional mapping from ServiceKey to group_id.
                                      If None, auto-assign group_id sequentially.

        Returns:
            Number of records inserted
        """
        if not self._cursor or not self._conn:
            raise RuntimeError("Database not connected")

        # Get pcap_ids for both files
        pcap_id_a = pcap_id_mapping.get(file1_path, 0)
        pcap_id_b = pcap_id_mapping.get(file2_path, 1)

        logger.info("Writing service statistics to database...")
        logger.info(f"  File A pcap_id: {pcap_id_a}")
        logger.info(f"  File B pcap_id: {pcap_id_b}")
        logger.info(f"  Total services: {len(service_stats)}")

        records_inserted = 0

        # Auto-assign group_id if no mapping provided
        if service_to_group_mapping is None:
            service_to_group_mapping = {}
            for idx, service in enumerate(service_stats, start=1):
                service_to_group_mapping[service.service_key] = idx
        else:
            # If mapping is provided, ensure all services have a group_id
            # Auto-assign for services not in the mapping
            max_group_id = max(service_to_group_mapping.values()) if service_to_group_mapping else 0
            next_group_id = max_group_id + 1
            for service in service_stats:
                if service.service_key not in service_to_group_mapping:
                    service_to_group_mapping[service.service_key] = next_group_id
                    next_group_id += 1

        # Process each service using unified data generation
        for service in service_stats:
            group_id = service_to_group_mapping[service.service_key]

            proto_str = (
                "TCP"
                if service.service_key.protocol == 6
                else (
                    "UDP"
                    if service.service_key.protocol == 17
                    else f"Proto{service.service_key.protocol}"
                )
            )

            logger.info(
                f"  Service: Port {service.service_key.server_port} ({proto_str}) -> Group {group_id}"
            )
            logger.info(f"    Total connections: {service.total_connections}")
            logger.info(
                f"    Server IPs: A={sorted(service.unique_server_ips_a)}, "
                f"B={sorted(service.unique_server_ips_b)}"
            )
            logger.info(
                f"    Client IPs: A={sorted(service.unique_client_ips_a)}, "
                f"B={sorted(service.unique_client_ips_b)}"
            )

            # Generate unified node data
            nodes = self._generate_service_nodes(
                group_id=group_id,
                service=service,
                pcap_id_a=pcap_id_a,
                pcap_id_b=pcap_id_b,
            )

            # Insert each node into database
            for node in nodes:
                self.insert_node(**node)
                records_inserted += 1

        return records_inserted

    @staticmethod
    def _generate_endpoint_pair_nodes(
        group_id: int,
        stat: EndpointPairStats,
        pcap_id_a: int,
        pcap_id_b: int,
    ) -> list[dict]:
        """
        Generate unified node data for an endpoint pair.

        This is the single source of truth for endpoint pair node generation.
        Both database and JSON writers use this method to ensure 100% consistency.

        Args:
            group_id: Group ID for this endpoint pair
            stat: EndpointPairStats object
            pcap_id_a: PCAP ID for file A
            pcap_id_b: PCAP ID for file B

        Returns:
            List of node data dictionaries with the following structure:
            {
                "pcap_id": int,
                "group_id": int,
                "ip": str | None,
                "port": int | None,
                "proto": int | None,
                "node_type": int,
                "is_capture": bool,
                "net_area": list[int],
                "stream_cnt": int,
                "pktlen": int,
                "display_name": str,
            }
        """
        nodes = []

        # Get protocol numbers from endpoint tuples
        proto_a = stat.tuple_a.protocol
        proto_b = stat.tuple_b.protocol

        # Determine network position based on TTL deltas
        position = MatchDatabaseWriter._determine_network_position_static(
            client_hops_a=stat.client_hops_a,
            server_hops_a=stat.server_hops_a,
            client_hops_b=stat.client_hops_b,
            server_hops_b=stat.server_hops_b,
            client_ttl_a=stat.client_ttl_a,
            server_ttl_a=stat.server_ttl_a,
            client_ttl_b=stat.client_ttl_b,
            server_ttl_b=stat.server_ttl_b,
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
        nodes.append(
            {
                "pcap_id": pcap_id_a,
                "group_id": group_id,
                "ip": stat.tuple_a.client_ip,
                "port": None,
                "proto": None,
                "node_type": 1,
                "is_capture": False,
                "net_area": net_area_a_client,
                "stream_cnt": 0,
                "pktlen": 0,
                "display_name": "",
            }
        )

        # File A - Network device between client and capture point (type=1001)
        if stat.client_hops_a > 0 and position != "B_CLOSER_TO_CLIENT":
            nodes.append(
                {
                    "pcap_id": pcap_id_a,
                    "group_id": group_id,
                    "ip": None,
                    "port": None,
                    "proto": None,
                    "node_type": 1001,
                    "is_capture": False,
                    "net_area": [],
                    "stream_cnt": 0,
                    "pktlen": 0,
                    "display_name": f"Network Device (Client-Capture, {stat.client_hops_a} hops)",
                }
            )

        # File A - Server node (type=2, with port)
        nodes.append(
            {
                "pcap_id": pcap_id_a,
                "group_id": group_id,
                "ip": stat.tuple_a.server_ip,
                "port": stat.tuple_a.server_port,
                "proto": proto_a,
                "node_type": 2,
                "is_capture": False,
                "net_area": net_area_a_server,
                "stream_cnt": stat.count,
                "pktlen": stat.total_bytes_a,
                "display_name": "",
            }
        )

        # File A - Network device between capture point and server (type=1002)
        if stat.server_hops_a > 0 and position != "A_CLOSER_TO_CLIENT":
            nodes.append(
                {
                    "pcap_id": pcap_id_a,
                    "group_id": group_id,
                    "ip": None,
                    "port": None,
                    "proto": None,
                    "node_type": 1002,
                    "is_capture": False,
                    "net_area": [],
                    "stream_cnt": 0,
                    "pktlen": 0,
                    "display_name": f"Network Device (Capture-Server, {stat.server_hops_a} hops)",
                }
            )

        # File B - Client node (type=1, no port)
        nodes.append(
            {
                "pcap_id": pcap_id_b,
                "group_id": group_id,
                "ip": stat.tuple_b.client_ip,
                "port": None,
                "proto": None,
                "node_type": 1,
                "is_capture": False,
                "net_area": net_area_b_client,
                "stream_cnt": 0,
                "pktlen": 0,
                "display_name": "",
            }
        )

        # File B - Network device between client and capture point (type=1001)
        if stat.client_hops_b > 0 and position != "A_CLOSER_TO_CLIENT":
            nodes.append(
                {
                    "pcap_id": pcap_id_b,
                    "group_id": group_id,
                    "ip": None,
                    "port": None,
                    "proto": None,
                    "node_type": 1001,
                    "is_capture": False,
                    "net_area": [],
                    "stream_cnt": 0,
                    "pktlen": 0,
                    "display_name": f"Network Device (Client-Capture, {stat.client_hops_b} hops)",
                }
            )

        # File B - Server node (type=2, with port)
        nodes.append(
            {
                "pcap_id": pcap_id_b,
                "group_id": group_id,
                "ip": stat.tuple_b.server_ip,
                "port": stat.tuple_b.server_port,
                "proto": proto_b,
                "node_type": 2,
                "is_capture": False,
                "net_area": net_area_b_server,
                "stream_cnt": stat.count,
                "pktlen": stat.total_bytes_b,
                "display_name": "",
            }
        )

        # File B - Network device between capture point and server (type=1002)
        if stat.server_hops_b > 0 and position != "B_CLOSER_TO_CLIENT":
            nodes.append(
                {
                    "pcap_id": pcap_id_b,
                    "group_id": group_id,
                    "ip": None,
                    "port": None,
                    "proto": None,
                    "node_type": 1002,
                    "is_capture": False,
                    "net_area": [],
                    "stream_cnt": 0,
                    "pktlen": 0,
                    "display_name": f"Network Device (Capture-Server, {stat.server_hops_b} hops)",
                }
            )

        return nodes

    @staticmethod
    def _generate_service_nodes(
        group_id: int,
        service: ServiceStats,
        pcap_id_a: int,
        pcap_id_b: int,
    ) -> list[dict]:
        """
        Generate unified node data for a service.

        This is the single source of truth for service node generation.
        Both database and JSON writers use this method to ensure 100% consistency.

        IMPORTANT: This method correctly handles the case where File A and File B
        may use different ports for the same service (e.g., due to NAT/load balancing).
        For File B server nodes, it uses the actual port from File B's endpoint pairs.

        Args:
            group_id: Group ID for this service
            service: ServiceStats object
            pcap_id_a: PCAP ID for file A
            pcap_id_b: PCAP ID for file B

        Returns:
            List of node data dictionaries with the same structure as _generate_endpoint_pair_nodes
        """
        nodes = []

        # Get protocol and port from service key
        protocol = service.service_key.protocol
        server_port = service.service_key.server_port

        # Calculate total bytes for the service (sum across all endpoint pairs)
        total_bytes_a = sum(pair.total_bytes_a for pair in service.endpoint_pairs)
        total_bytes_b = sum(pair.total_bytes_b for pair in service.endpoint_pairs)

        # Determine network position based on the first endpoint pair
        # (all pairs in the same service should have similar topology)
        first_pair = service.endpoint_pairs[0]
        position = MatchDatabaseWriter._determine_network_position_static(
            client_hops_a=first_pair.client_hops_a,
            server_hops_a=first_pair.server_hops_a,
            client_hops_b=first_pair.client_hops_b,
            server_hops_b=first_pair.server_hops_b,
            client_ttl_a=first_pair.client_ttl_a,
            server_ttl_a=first_pair.server_ttl_a,
            client_ttl_b=first_pair.client_ttl_b,
            server_ttl_b=first_pair.server_ttl_b,
        )

        # Determine net_area based on position
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

        # File A - Client nodes (type=1, no port)
        for client_ip in sorted(service.unique_client_ips_a):
            nodes.append(
                {
                    "pcap_id": pcap_id_a,
                    "group_id": group_id,
                    "ip": client_ip,
                    "port": None,
                    "proto": None,
                    "node_type": 1,
                    "is_capture": False,
                    "net_area": net_area_a_client,
                    "stream_cnt": 0,
                    "pktlen": 0,
                    "display_name": "",
                }
            )

        # File A - Network device between client and capture point (type=1001)
        if first_pair.client_hops_a > 0 and position != "B_CLOSER_TO_CLIENT":
            nodes.append(
                {
                    "pcap_id": pcap_id_a,
                    "group_id": group_id,
                    "ip": None,
                    "port": None,
                    "proto": None,
                    "node_type": 1001,
                    "is_capture": False,
                    "net_area": [],
                    "stream_cnt": 0,
                    "pktlen": 0,
                    "display_name": "",
                }
            )

        # File A - Server nodes (type=2, with port)
        for server_ip in sorted(service.unique_server_ips_a):
            nodes.append(
                {
                    "pcap_id": pcap_id_a,
                    "group_id": group_id,
                    "ip": server_ip,
                    "port": server_port,
                    "proto": protocol,
                    "node_type": 2,
                    "is_capture": False,
                    "net_area": net_area_a_server,
                    "stream_cnt": service.total_connections,
                    "pktlen": total_bytes_a,
                    "display_name": "",
                }
            )

        # File A - Network device between capture point and server (type=1002)
        if first_pair.server_hops_a > 0 and position != "A_CLOSER_TO_CLIENT":
            nodes.append(
                {
                    "pcap_id": pcap_id_a,
                    "group_id": group_id,
                    "ip": None,
                    "port": None,
                    "proto": None,
                    "node_type": 1002,
                    "is_capture": False,
                    "net_area": [],
                    "stream_cnt": 0,
                    "pktlen": 0,
                    "display_name": "",
                }
            )

        # File B - Client nodes (type=1, no port)
        for client_ip in sorted(service.unique_client_ips_b):
            nodes.append(
                {
                    "pcap_id": pcap_id_b,
                    "group_id": group_id,
                    "ip": client_ip,
                    "port": None,
                    "proto": None,
                    "node_type": 1,
                    "is_capture": False,
                    "net_area": net_area_b_client,
                    "stream_cnt": 0,
                    "pktlen": 0,
                    "display_name": "",
                }
            )

        # File B - Network device between client and capture point (type=1001)
        if first_pair.client_hops_b > 0 and position != "A_CLOSER_TO_CLIENT":
            nodes.append(
                {
                    "pcap_id": pcap_id_b,
                    "group_id": group_id,
                    "ip": None,
                    "port": None,
                    "proto": None,
                    "node_type": 1001,
                    "is_capture": False,
                    "net_area": [],
                    "stream_cnt": 0,
                    "pktlen": 0,
                    "display_name": "",
                }
            )

        # File B - Server nodes (type=2, with port)
        # CRITICAL FIX: For each server IP in file B, use the actual port from file B
        # (which may differ from file A due to NAT/load balancing)
        server_ip_to_port_b: dict[str, int] = {}
        for pair in service.endpoint_pairs:
            server_ip_b = pair.tuple_b.server_ip
            server_port_b = pair.tuple_b.server_port
            # Store the port for this server IP (all pairs should have same port for same IP)
            if server_ip_b not in server_ip_to_port_b:
                server_ip_to_port_b[server_ip_b] = server_port_b

        for server_ip in sorted(service.unique_server_ips_b):
            # Use the actual port from file B for this server IP
            actual_port_b = server_ip_to_port_b.get(server_ip, server_port)
            nodes.append(
                {
                    "pcap_id": pcap_id_b,
                    "group_id": group_id,
                    "ip": server_ip,
                    "port": actual_port_b,
                    "proto": protocol,
                    "node_type": 2,
                    "is_capture": False,
                    "net_area": net_area_b_server,
                    "stream_cnt": service.total_connections,
                    "pktlen": total_bytes_b,
                    "display_name": "",
                }
            )

        # File B - Network device between capture point and server (type=1002)
        if first_pair.server_hops_b > 0 and position != "B_CLOSER_TO_CLIENT":
            nodes.append(
                {
                    "pcap_id": pcap_id_b,
                    "group_id": group_id,
                    "ip": None,
                    "port": None,
                    "proto": None,
                    "node_type": 1002,
                    "is_capture": False,
                    "net_area": [],
                    "stream_cnt": 0,
                    "pktlen": 0,
                    "display_name": "",
                }
            )

        return nodes

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

        # Process each endpoint pair using unified data generation
        for group_id, stat in enumerate(endpoint_stats, start=1):
            # Generate unified node data
            nodes = MatchDatabaseWriter._generate_endpoint_pair_nodes(
                group_id=group_id,
                stat=stat,
                pcap_id_a=pcap_id_a,
                pcap_id_b=pcap_id_b,
            )

            # Convert to JSON format (rename node_type to type, add metrics field)
            for node in nodes:
                json_node = node.copy()
                json_node["type"] = json_node.pop("node_type")  # Rename for JSON output
                json_node["metrics"] = {"stream_cnt": node["stream_cnt"]}
                records.append(json_node)

        # Create parent directory if it doesn't exist
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write to file (one JSON object per line)
        with open(output_file, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

        logger.info(f"Successfully wrote {len(records)} records to {output_file}")
        return len(records)

    @staticmethod
    def write_service_stats_to_json(
        service_stats: list,  # list[ServiceStats]
        pcap_id_mapping: dict[str, int],
        file1_path: str,
        file2_path: str,
        output_file: Path,
        service_to_group_mapping: dict | None = None,  # dict[ServiceKey, int]
    ) -> int:
        """
        Write service statistics to JSON file.

        Each service gets one group_id. All unique client IPs and server IPs
        within the service are written as separate nodes, but without preserving
        the client-server pairing relationship.

        Args:
            service_stats: List of ServiceStats objects
            pcap_id_mapping: Mapping from file path to pcap_id
            file1_path: Path to file A (as string)
            file2_path: Path to file B (as string)
            output_file: Path to output JSON file
            service_to_group_mapping: Optional mapping from ServiceKey to group_id.
                                      If None, auto-assign group_id sequentially.

        Returns:
            Number of records written
        """
        # Get pcap_ids for both files
        pcap_id_a = pcap_id_mapping.get(file1_path, 0)
        pcap_id_b = pcap_id_mapping.get(file2_path, 1)

        logger.info(f"Writing service statistics to JSON file: {output_file}")
        logger.info(f"  File A pcap_id: {pcap_id_a}")
        logger.info(f"  File B pcap_id: {pcap_id_b}")
        logger.info(f"  Total services: {len(service_stats)}")

        # Auto-assign group_id if no mapping provided
        if service_to_group_mapping is None:
            service_to_group_mapping = {}
            for idx, service in enumerate(service_stats, start=1):
                service_to_group_mapping[service.service_key] = idx
        else:
            # If mapping is provided, ensure all services have a group_id
            # Auto-assign for services not in the mapping
            max_group_id = max(service_to_group_mapping.values()) if service_to_group_mapping else 0
            next_group_id = max_group_id + 1
            for service in service_stats:
                if service.service_key not in service_to_group_mapping:
                    service_to_group_mapping[service.service_key] = next_group_id
                    next_group_id += 1

        records = []

        # Process each service using unified data generation
        for service in service_stats:
            group_id = service_to_group_mapping[service.service_key]

            # Generate unified node data
            nodes = MatchDatabaseWriter._generate_service_nodes(
                group_id=group_id,
                service=service,
                pcap_id_a=pcap_id_a,
                pcap_id_b=pcap_id_b,
            )

            # Convert to JSON format (rename node_type to type, add metrics field)
            for node in nodes:
                json_node = node.copy()
                json_node["type"] = json_node.pop("node_type")  # Rename for JSON output
                json_node["metrics"] = {"stream_cnt": node["stream_cnt"]}
                records.append(json_node)

        # Create parent directory if it doesn't exist
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write to file (one JSON object per line)
        with open(output_file, "w", encoding="utf-8") as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

        logger.info(f"Successfully wrote {len(records)} records to {output_file}")
        return len(records)

    @staticmethod
    def _determine_network_position_static(
        client_hops_a: int,
        server_hops_a: int,
        client_hops_b: int,
        server_hops_b: int,
        client_ttl_a: int = 0,
        server_ttl_a: int = 0,
        client_ttl_b: int = 0,
        server_ttl_b: int = 0,
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
            client_ttl_a: Original client TTL value from file A (optional)
            server_ttl_a: Original server TTL value from file A (optional)
            client_ttl_b: Original client TTL value from file B (optional)
            server_ttl_b: Original server TTL value from file B (optional)

        Returns:
            Position indicator string:
            - "A_CLOSER_TO_CLIENT": A is farther from server
            - "B_CLOSER_TO_CLIENT": B is farther from server
            - "A_CLOSER_TO_SERVER": A is closer to server
            - "B_CLOSER_TO_SERVER": B is closer to server
            - "SAME_POSITION": Same distance or cannot determine
        """
        # Check for original TTL values (common initial TTL values: 255, 128, 64)
        ORIGINAL_TTL_VALUES = {255, 128, 64}

        # Check if we have original TTL scenario
        client_a_is_original = client_ttl_a in ORIGINAL_TTL_VALUES
        server_a_is_original = server_ttl_a in ORIGINAL_TTL_VALUES
        client_b_is_original = client_ttl_b in ORIGINAL_TTL_VALUES
        server_b_is_original = server_ttl_b in ORIGINAL_TTL_VALUES

        # Special case: If one file has original client TTL and another has original server TTL
        # This indicates the capture points are on opposite sides of the connection
        # Rule: The point seeing original client TTL is closer to SERVER
        #       The point seeing original server TTL is closer to CLIENT
        # Reason: 255 is a network device (router/LB) TTL signature
        if (
            client_a_is_original
            and server_b_is_original
            and not server_a_is_original
            and not client_b_is_original
        ):
            # A sees original client TTL, B sees original server TTL
            # → A is closer to server, B is closer to client
            logger.debug(
                f"Original TTL detected: client_ttl_a={client_ttl_a} (original), "
                f"server_ttl_b={server_ttl_b} (original). B is closer to client."
            )
            return "B_CLOSER_TO_CLIENT"

        if (
            server_a_is_original
            and client_b_is_original
            and not client_a_is_original
            and not server_b_is_original
        ):
            # A sees original server TTL, B sees original client TTL
            # → A is closer to client, B is closer to server
            logger.debug(
                f"Original TTL detected: server_ttl_a={server_ttl_a} (original), "
                f"client_ttl_b={client_ttl_b} (original). A is closer to client."
            )
            return "A_CLOSER_TO_CLIENT"

        if (
            client_b_is_original
            and server_a_is_original
            and not server_b_is_original
            and not client_a_is_original
        ):
            # B sees original client TTL, A sees original server TTL
            # → B is closer to server, A is closer to client
            logger.debug(
                f"Original TTL detected: client_ttl_b={client_ttl_b} (original), "
                f"server_ttl_a={server_ttl_a} (original). A is closer to client."
            )
            return "A_CLOSER_TO_CLIENT"

        if (
            server_b_is_original
            and client_a_is_original
            and not client_b_is_original
            and not server_a_is_original
        ):
            # B sees original server TTL, A sees original client TTL
            # → B is closer to client, A is closer to server
            logger.debug(
                f"Original TTL detected: server_ttl_b={server_ttl_b} (original), "
                f"client_ttl_a={client_ttl_a} (original). B is closer to client."
            )
            return "B_CLOSER_TO_CLIENT"

        # Calculate TTL delta differences
        client_delta_diff = client_hops_b - client_hops_a
        server_delta_diff = server_hops_a - server_hops_b

        # Detect potential NAT scenario (client and server deltas conflict)
        is_nat_scenario = (client_delta_diff > 0 and server_delta_diff < 0) or (
            client_delta_diff < 0 and server_delta_diff > 0
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
