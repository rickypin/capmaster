"""Server detection module with multi-layer heuristics."""

from __future__ import annotations

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
    3. Traffic pattern analysis (packet/byte statistics)
    4. Port number comparison (fallback)
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

        # Priority 3: Traffic pattern analysis
        # Note: This requires packet-level data which is not available in TcpConnection
        # We skip this for now and go to fallback

        # Priority 4: Fallback - use original detection
        return self._detect_fallback(connection)

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

