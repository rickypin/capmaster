"""Server detection module with multi-layer heuristics."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from capmaster.plugins.match.connection import TcpConnection


@dataclass
class ServerInfo:
    """Server detection information."""

    server_ip: str
    """Server IP address"""

    server_port: int
    """Server port number"""

    client_ip: str
    """Client IP address"""

    client_port: int
    """Client port number"""

    confidence: str
    """Confidence level: HIGH, MEDIUM, LOW, VERY_LOW, UNKNOWN"""

    method: str
    """Detection method: SYN_PACKET, PORT_HEURISTIC, TRAFFIC_PATTERN, FALLBACK"""


class ServerDetector:
    """
    Multi-layer server detector.

    Uses multiple heuristics to determine which side is the server:
    1. SYN packet direction (most reliable)
    2. Port number heuristics (well-known ports)
    3. Cardinality-based detection (one IP:Port serves multiple clients)
    4. Traffic pattern analysis (packet/byte statistics)
    5. Port number comparison (fallback)
    """

    # Well-known ports (IANA registered 0-1023 + common services)
    WELL_KNOWN_PORTS = {
        20, 21,      # FTP
        22,          # SSH
        23,          # Telnet
        25,          # SMTP
        53,          # DNS
        80,          # HTTP
        110,         # POP3
        143,         # IMAP
        443,         # HTTPS
        465,         # SMTPS
        587,         # SMTP submission
        993,         # IMAPS
        995,         # POP3S
        3389,        # RDP
        5900,        # VNC
        8080,        # HTTP alternate
        8443,        # HTTPS alternate
    }

    # Database ports (extended list)
    DATABASE_PORTS = {
        1433,        # MS SQL Server
        1521,        # Oracle
        3306,        # MySQL
        5432,        # PostgreSQL
        6379,        # Redis
        7000, 7001,  # Cassandra
        8529,        # ArangoDB
        9042,        # Cassandra CQL
        27017,       # MongoDB
        50000,       # DB2
    }

    def __init__(self):
        """Initialize the detector with cardinality tracking."""
        # Track unique client IPs for each IP:Port combination
        # Key: (ip, port), Value: set of client IPs
        self._endpoint_clients: dict[tuple[str, int], set[str]] = defaultdict(set)

        # Track unique server IP:Port combinations for each client IP
        # Key: client_ip, Value: set of (server_ip, server_port) tuples
        self._client_servers: dict[str, set[tuple[str, int]]] = defaultdict(set)

        # Track unique server IPs for each port number
        # Key: port, Value: set of IPs using this port as server
        self._port_server_ips: dict[int, set[str]] = defaultdict(set)

        # Track unique client IPs for each port number
        # Key: port, Value: set of IPs using this port as client
        self._port_client_ips: dict[int, set[str]] = defaultdict(set)

        # Track port stability: for each IP:Port, track the set of peer ports it connects to
        # This helps identify "one port connects to many peer ports" pattern (server characteristic)
        # Key: (ip, port), Value: set of peer ports
        self._endpoint_peer_ports: dict[tuple[str, int], set[int]] = defaultdict(set)

        # Flag to indicate if cardinality analysis is available
        self._cardinality_ready = False

    def collect_connection(self, connection: TcpConnection) -> None:
        """
        Collect connection information for cardinality analysis.

        This should be called for all connections before detection to build
        the cardinality statistics.

        Args:
            connection: TCP connection to collect
        """
        # Track both directions to handle cases where we don't know which is server yet
        # Direction 1: server_ip:server_port -> client_ip
        self._endpoint_clients[(connection.server_ip, connection.server_port)].add(
            connection.client_ip
        )
        self._client_servers[connection.client_ip].add(
            (connection.server_ip, connection.server_port)
        )
        # Track port usage pattern
        self._port_server_ips[connection.server_port].add(connection.server_ip)
        self._port_client_ips[connection.server_port].add(connection.client_ip)
        # Track port stability: server_ip:server_port connects to client_port
        self._endpoint_peer_ports[(connection.server_ip, connection.server_port)].add(
            connection.client_port
        )

        # Direction 2: client_ip:client_port -> server_ip
        self._endpoint_clients[(connection.client_ip, connection.client_port)].add(
            connection.server_ip
        )
        self._client_servers[connection.server_ip].add(
            (connection.client_ip, connection.client_port)
        )
        # Track port usage pattern
        self._port_server_ips[connection.client_port].add(connection.client_ip)
        self._port_client_ips[connection.client_port].add(connection.server_ip)
        # Track port stability: client_ip:client_port connects to server_port
        self._endpoint_peer_ports[(connection.client_ip, connection.client_port)].add(
            connection.server_port
        )

    def finalize_cardinality(self) -> None:
        """
        Finalize cardinality analysis after all connections are collected.

        This should be called after all collect_connection() calls are done.
        """
        self._cardinality_ready = True

    def detect(self, connection: TcpConnection) -> ServerInfo:
        """
        Detect server using multi-layer approach.

        Args:
            connection: TCP connection to analyze

        Returns:
            ServerInfo with detected server/client and confidence level
        """
        # Priority 1: SYN packet direction (most reliable)
        if connection.syn_options:
            return self._detect_by_syn(connection)

        # Priority 2: Port number heuristics
        info = self._detect_by_port(connection)
        if info.confidence in ["HIGH", "MEDIUM"]:
            return info

        # Priority 3: Cardinality-based detection (new!)
        if self._cardinality_ready:
            info = self._detect_by_cardinality(connection)
            if info.confidence in ["HIGH", "MEDIUM"]:
                return info

        # Priority 4: Traffic pattern analysis
        # Note: This requires packet-level data which is not available in TcpConnection
        # We skip this for now and go to fallback

        # Priority 5: Fallback - use original detection
        return self._detect_fallback(connection)

    def _detect_by_cardinality(self, connection: TcpConnection) -> ServerInfo:
        """
        Detect server by cardinality analysis.

        Uses three key characteristics:
        1. A server IP:Port typically serves multiple client IPs (high cardinality)
        2. Multiple server IPs often use the same port to provide services (port reuse pattern)
        3. A server IP:Port uses the same port to connect to multiple peer ports (port stability)

        Args:
            connection: TCP connection to analyze

        Returns:
            ServerInfo with confidence based on cardinality difference
        """
        # Get cardinality for both endpoints
        endpoint1 = (connection.server_ip, connection.server_port)
        endpoint2 = (connection.client_ip, connection.client_port)

        cardinality1 = len(self._endpoint_clients.get(endpoint1, set()))
        cardinality2 = len(self._endpoint_clients.get(endpoint2, set()))

        # Get port reuse patterns
        port1_server_ips = len(self._port_server_ips.get(connection.server_port, set()))
        port1_client_ips = len(self._port_client_ips.get(connection.server_port, set()))
        port2_server_ips = len(self._port_server_ips.get(connection.client_port, set()))
        port2_client_ips = len(self._port_client_ips.get(connection.client_port, set()))

        # Get port stability patterns (how many different peer ports each endpoint connects to)
        peer_ports1 = len(self._endpoint_peer_ports.get(endpoint1, set()))
        peer_ports2 = len(self._endpoint_peer_ports.get(endpoint2, set()))

        # Minimum thresholds
        MIN_SERVER_CLIENTS = 2  # At least 2 different client IPs
        MIN_PORT_REUSE = 2  # At least 2 different server IPs using the same port
        MIN_PEER_PORTS = 2  # At least 2 different peer ports (port stability indicator)

        # Case 1: Clear server pattern - one endpoint serves multiple clients
        if cardinality1 >= MIN_SERVER_CLIENTS and cardinality2 < MIN_SERVER_CLIENTS:
            # endpoint1 (server_ip:server_port) is the server
            confidence = "HIGH" if cardinality1 >= 5 else "MEDIUM"

            # Boost confidence if port shows server reuse pattern
            if port1_server_ips >= MIN_PORT_REUSE and port2_server_ips < MIN_PORT_REUSE:
                confidence = "HIGH"
                method = f"CARDINALITY_PORT_REUSE_{cardinality1}v{cardinality2}_P{port1_server_ips}"
            else:
                method = f"CARDINALITY_{cardinality1}v{cardinality2}"

            return ServerInfo(
                server_ip=connection.server_ip,
                server_port=connection.server_port,
                client_ip=connection.client_ip,
                client_port=connection.client_port,
                confidence=confidence,
                method=method,
            )

        if cardinality2 >= MIN_SERVER_CLIENTS and cardinality1 < MIN_SERVER_CLIENTS:
            # endpoint2 (client_ip:client_port) is actually the server, need to swap
            confidence = "HIGH" if cardinality2 >= 5 else "MEDIUM"

            # Boost confidence if port shows server reuse pattern
            if port2_server_ips >= MIN_PORT_REUSE and port1_server_ips < MIN_PORT_REUSE:
                confidence = "HIGH"
                method = f"CARDINALITY_PORT_REUSE_SWAPPED_{cardinality2}v{cardinality1}_P{port2_server_ips}"
            else:
                method = f"CARDINALITY_SWAPPED_{cardinality2}v{cardinality1}"

            return ServerInfo(
                server_ip=connection.client_ip,
                server_port=connection.client_port,
                client_ip=connection.server_ip,
                client_port=connection.server_port,
                confidence=confidence,
                method=method,
            )

        # Case 2: Port reuse pattern - multiple server IPs using the same port
        # This is a strong indicator even if individual endpoint cardinality is low
        if port1_server_ips >= MIN_PORT_REUSE and port2_server_ips < MIN_PORT_REUSE:
            # port1 shows server reuse pattern (multiple IPs using this port as server)
            return ServerInfo(
                server_ip=connection.server_ip,
                server_port=connection.server_port,
                client_ip=connection.client_ip,
                client_port=connection.client_port,
                confidence="MEDIUM",
                method=f"PORT_REUSE_{port1_server_ips}servers_on_port{connection.server_port}",
            )

        if port2_server_ips >= MIN_PORT_REUSE and port1_server_ips < MIN_PORT_REUSE:
            # port2 shows server reuse pattern, need to swap
            return ServerInfo(
                server_ip=connection.client_ip,
                server_port=connection.client_port,
                client_ip=connection.server_ip,
                client_port=connection.server_port,
                confidence="MEDIUM",
                method=f"PORT_REUSE_SWAPPED_{port2_server_ips}servers_on_port{connection.client_port}",
            )

        # Case 3: Port stability pattern - one endpoint uses same port to connect to multiple peer ports
        # This is a strong indicator of server behavior even when IP cardinality is low (e.g., point-to-point)
        # Example: B:60001 connects to A:50001, A:50002, A:50003 → B:60001 is likely the server
        if peer_ports1 >= MIN_PEER_PORTS and peer_ports2 < MIN_PEER_PORTS:
            # endpoint1 shows port stability (same port, multiple peer ports)
            return ServerInfo(
                server_ip=connection.server_ip,
                server_port=connection.server_port,
                client_ip=connection.client_ip,
                client_port=connection.client_port,
                confidence="MEDIUM",
                method=f"PORT_STABILITY_{peer_ports1}peer_ports",
            )

        if peer_ports2 >= MIN_PEER_PORTS and peer_ports1 < MIN_PEER_PORTS:
            # endpoint2 shows port stability, need to swap
            return ServerInfo(
                server_ip=connection.client_ip,
                server_port=connection.client_port,
                client_ip=connection.server_ip,
                client_port=connection.server_port,
                confidence="MEDIUM",
                method=f"PORT_STABILITY_SWAPPED_{peer_ports2}peer_ports",
            )

        # Case 4: Both have high cardinality or both have low cardinality
        # Use the ratio to make a decision if there's a significant difference
        if cardinality1 > 0 and cardinality2 > 0:
            ratio = max(cardinality1, cardinality2) / min(cardinality1, cardinality2)

            # If ratio is significant (e.g., 3:1 or higher), use the higher one as server
            if ratio >= 3.0:
                if cardinality1 > cardinality2:
                    return ServerInfo(
                        server_ip=connection.server_ip,
                        server_port=connection.server_port,
                        client_ip=connection.client_ip,
                        client_port=connection.client_port,
                        confidence="MEDIUM",
                        method=f"CARDINALITY_RATIO_{cardinality1}v{cardinality2}",
                    )
                else:
                    return ServerInfo(
                        server_ip=connection.client_ip,
                        server_port=connection.client_port,
                        client_ip=connection.server_ip,
                        client_port=connection.server_port,
                        confidence="MEDIUM",
                        method=f"CARDINALITY_RATIO_SWAPPED_{cardinality2}v{cardinality1}",
                    )

        # No clear cardinality-based determination
        return ServerInfo(
            server_ip=connection.server_ip,
            server_port=connection.server_port,
            client_ip=connection.client_ip,
            client_port=connection.client_port,
            confidence="UNKNOWN",
            method=f"CARDINALITY_UNCLEAR_C{cardinality1}v{cardinality2}_PR{port1_server_ips}v{port2_server_ips}_PS{peer_ports1}v{peer_ports2}",
        )

    def _detect_by_syn(self, connection: TcpConnection) -> ServerInfo:
        """
        Detect server by SYN packet direction.

        The destination of the SYN packet is the server.

        Args:
            connection: TCP connection with SYN packet

        Returns:
            ServerInfo with HIGH confidence
        """
        return ServerInfo(
            server_ip=connection.server_ip,
            server_port=connection.server_port,
            client_ip=connection.client_ip,
            client_port=connection.client_port,
            confidence="HIGH",
            method="SYN_PACKET",
        )

    def _detect_by_port(self, connection: TcpConnection) -> ServerInfo:
        """
        Detect server by port number heuristics.

        Uses well-known ports and database ports to determine server side.

        Args:
            connection: TCP connection to analyze

        Returns:
            ServerInfo with confidence based on port matching
        """
        port1 = connection.client_port
        port2 = connection.server_port

        # Case 1: One is well-known port, other is not
        if port1 in self.WELL_KNOWN_PORTS and port2 not in self.WELL_KNOWN_PORTS:
            # client_port is well-known, need to swap
            return ServerInfo(
                server_ip=connection.client_ip,
                server_port=connection.client_port,
                client_ip=connection.server_ip,
                client_port=connection.server_port,
                confidence="HIGH",
                method="PORT_HEURISTIC_SWAPPED",
            )
        if port2 in self.WELL_KNOWN_PORTS and port1 not in self.WELL_KNOWN_PORTS:
            # server_port is well-known, keep as is
            return ServerInfo(
                server_ip=connection.server_ip,
                server_port=connection.server_port,
                client_ip=connection.client_ip,
                client_port=connection.client_port,
                confidence="HIGH",
                method="PORT_HEURISTIC",
            )

        # Case 2: One is database port, other is not
        if port1 in self.DATABASE_PORTS and port2 not in self.DATABASE_PORTS:
            # client_port is database port, need to swap
            return ServerInfo(
                server_ip=connection.client_ip,
                server_port=connection.client_port,
                client_ip=connection.server_ip,
                client_port=connection.server_port,
                confidence="MEDIUM",
                method="PORT_HEURISTIC_SWAPPED",
            )
        if port2 in self.DATABASE_PORTS and port1 not in self.DATABASE_PORTS:
            # server_port is database port, keep as is
            return ServerInfo(
                server_ip=connection.server_ip,
                server_port=connection.server_port,
                client_ip=connection.client_ip,
                client_port=connection.client_port,
                confidence="MEDIUM",
                method="PORT_HEURISTIC",
            )

        # Case 3: One < 1024 (system port), other >= 1024
        if port1 < 1024 and port2 >= 1024:
            # client_port is system port, need to swap
            return ServerInfo(
                server_ip=connection.client_ip,
                server_port=connection.client_port,
                client_ip=connection.server_ip,
                client_port=connection.server_port,
                confidence="MEDIUM",
                method="PORT_HEURISTIC_SWAPPED",
            )
        if port2 < 1024 and port1 >= 1024:
            # server_port is system port, keep as is
            return ServerInfo(
                server_ip=connection.server_ip,
                server_port=connection.server_port,
                client_ip=connection.client_ip,
                client_port=connection.client_port,
                confidence="MEDIUM",
                method="PORT_HEURISTIC",
            )

        # No clear port-based determination
        return ServerInfo(
            server_ip=connection.server_ip,
            server_port=connection.server_port,
            client_ip=connection.client_ip,
            client_port=connection.client_port,
            confidence="UNKNOWN",
            method="PORT_HEURISTIC_FAILED",
        )

    def _detect_fallback(self, connection: TcpConnection) -> ServerInfo:
        """
        Fallback detection - use original connection detection.

        Args:
            connection: TCP connection

        Returns:
            ServerInfo with VERY_LOW confidence
        """
        # Use smaller port number as server (common heuristic)
        if connection.server_port < connection.client_port:
            return ServerInfo(
                server_ip=connection.server_ip,
                server_port=connection.server_port,
                client_ip=connection.client_ip,
                client_port=connection.client_port,
                confidence="VERY_LOW",
                method="FALLBACK_PORT_COMPARISON",
            )
        else:
            # Swap if client port is smaller
            return ServerInfo(
                server_ip=connection.client_ip,
                server_port=connection.client_port,
                client_ip=connection.server_ip,
                client_port=connection.server_port,
                confidence="VERY_LOW",
                method="FALLBACK_PORT_COMPARISON_SWAPPED",
            )

