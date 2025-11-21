"""Serialization and deserialization for ConnectionMatch objects."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from capmaster.core.connection.matcher import ConnectionMatch
from capmaster.core.connection.models import TcpConnection
from capmaster.core.connection.scorer import MatchScore

logger = logging.getLogger(__name__)


class MatchSerializer:
    """Serialize and deserialize ConnectionMatch objects to/from JSON."""

    @staticmethod
    def serialize_connection(conn: TcpConnection) -> dict[str, Any]:
        """
        Serialize a TcpConnection to a dictionary.

        Args:
            conn: TcpConnection object to serialize

        Returns:
            Dictionary representation of the connection
        """
        return {
            "stream_id": conn.stream_id,
            "protocol": conn.protocol,
            "client_ip": conn.client_ip,
            "client_port": conn.client_port,
            "server_ip": conn.server_ip,
            "server_port": conn.server_port,
            "syn_timestamp": conn.syn_timestamp,
            "syn_options": conn.syn_options,
            "has_syn": conn.has_syn,
            "client_isn": conn.client_isn,
            "server_isn": conn.server_isn,
            "tcp_timestamp_tsval": conn.tcp_timestamp_tsval,
            "tcp_timestamp_tsecr": conn.tcp_timestamp_tsecr,
            "client_payload_md5": conn.client_payload_md5,
            "server_payload_md5": conn.server_payload_md5,
            "length_signature": conn.length_signature,
            "is_header_only": conn.is_header_only,
            "ipid_first": conn.ipid_first,
            "ipid_set": list(conn.ipid_set),
            "client_ipid_set": list(conn.client_ipid_set),
            "server_ipid_set": list(conn.server_ipid_set),
            "first_packet_time": conn.first_packet_time,
            "last_packet_time": conn.last_packet_time,
            "packet_count": conn.packet_count,
            "client_ttl": conn.client_ttl,
            "server_ttl": conn.server_ttl,
            "total_bytes": conn.total_bytes,
        }

    @staticmethod
    def deserialize_connection(data: dict[str, Any]) -> TcpConnection:
        """
        Deserialize a dictionary to a TcpConnection.

        Args:
            data: Dictionary representation of the connection

        Returns:
            TcpConnection object
        """
        return TcpConnection(
            stream_id=data["stream_id"],
            protocol=data["protocol"],
            client_ip=data["client_ip"],
            client_port=data["client_port"],
            server_ip=data["server_ip"],
            server_port=data["server_port"],
            syn_timestamp=data["syn_timestamp"],
            syn_options=data["syn_options"],
            has_syn=data.get("has_syn", False),
            client_isn=data["client_isn"],
            server_isn=data["server_isn"],
            tcp_timestamp_tsval=data["tcp_timestamp_tsval"],
            tcp_timestamp_tsecr=data["tcp_timestamp_tsecr"],
            client_payload_md5=data["client_payload_md5"],
            server_payload_md5=data["server_payload_md5"],
            length_signature=data["length_signature"],
            is_header_only=data["is_header_only"],
            ipid_first=data["ipid_first"],
            ipid_set=set(data["ipid_set"]),
            client_ipid_set=set(data["client_ipid_set"]),
            server_ipid_set=set(data["server_ipid_set"]),
            first_packet_time=data["first_packet_time"],
            last_packet_time=data["last_packet_time"],
            packet_count=data["packet_count"],
            client_ttl=data["client_ttl"],
            server_ttl=data["server_ttl"],
            total_bytes=data.get("total_bytes", 0),
        )

    @staticmethod
    def serialize_score(score: MatchScore) -> dict[str, Any]:
        """
        Serialize a MatchScore to a dictionary.

        Args:
            score: MatchScore object to serialize

        Returns:
            Dictionary representation of the score
        """
        return {
            "normalized_score": score.normalized_score,
            "raw_score": score.raw_score,
            "available_weight": score.available_weight,
            "ipid_match": score.ipid_match,
            "evidence": score.evidence,
            "force_accept": score.force_accept,
            "microflow_accept": score.microflow_accept,
        }

    @staticmethod
    def deserialize_score(data: dict[str, Any]) -> MatchScore:
        """
        Deserialize a dictionary to a MatchScore.

        Args:
            data: Dictionary representation of the score

        Returns:
            MatchScore object
        """
        return MatchScore(
            normalized_score=data["normalized_score"],
            raw_score=data["raw_score"],
            available_weight=data["available_weight"],
            ipid_match=data["ipid_match"],
            evidence=data["evidence"],
            force_accept=data["force_accept"],
            microflow_accept=data["microflow_accept"],
        )

    @staticmethod
    def serialize_match(match: ConnectionMatch) -> dict[str, Any]:
        """
        Serialize a ConnectionMatch to a dictionary.

        Args:
            match: ConnectionMatch object to serialize

        Returns:
            Dictionary representation of the match
        """
        return {
            "conn1": MatchSerializer.serialize_connection(match.conn1),
            "conn2": MatchSerializer.serialize_connection(match.conn2),
            "score": MatchSerializer.serialize_score(match.score),
        }

    @staticmethod
    def deserialize_match(data: dict[str, Any]) -> ConnectionMatch:
        """
        Deserialize a dictionary to a ConnectionMatch.

        Args:
            data: Dictionary representation of the match

        Returns:
            ConnectionMatch object
        """
        return ConnectionMatch(
            conn1=MatchSerializer.deserialize_connection(data["conn1"]),
            conn2=MatchSerializer.deserialize_connection(data["conn2"]),
            score=MatchSerializer.deserialize_score(data["score"]),
        )

    @staticmethod
    def save_matches(
        matches: list[ConnectionMatch],
        output_file: Path,
        file1_path: str,
        file2_path: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Save matches to a JSON file.

        Args:
            matches: List of ConnectionMatch objects
            output_file: Path to output JSON file
            file1_path: Path to first PCAP file
            file2_path: Path to second PCAP file
            metadata: Optional metadata to include in the output
        """
        data = {
            "version": "1.0",
            "file1": str(file1_path),
            "file2": str(file2_path),
            "metadata": metadata or {},
            "matches": [MatchSerializer.serialize_match(m) for m in matches],
        }

        # Create parent directory if it doesn't exist
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Write to file
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"Saved {len(matches)} matches to {output_file}")

    @staticmethod
    def load_matches(input_file: Path) -> tuple[list[ConnectionMatch], dict[str, Any]]:
        """
        Load matches from a JSON file.

        Args:
            input_file: Path to input JSON file

        Returns:
            Tuple of (matches, metadata) where:
            - matches: List of ConnectionMatch objects
            - metadata: Dictionary containing file paths and other metadata

        Raises:
            FileNotFoundError: If input file doesn't exist
            ValueError: If file format is invalid
        """
        if not input_file.exists():
            raise FileNotFoundError(f"Match file not found: {input_file}")

        try:
            with open(input_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Validate version
            version = data.get("version")
            if version != "1.0":
                logger.warning(f"Unknown match file version: {version}")

            # Extract metadata
            metadata = {
                "file1": data.get("file1"),
                "file2": data.get("file2"),
                "version": version,
                **data.get("metadata", {}),
            }

            # Deserialize matches
            matches = [
                MatchSerializer.deserialize_match(m) for m in data.get("matches", [])
            ]

            logger.info(f"Loaded {len(matches)} matches from {input_file}")
            return matches, metadata

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format in match file: {e}")
        except KeyError as e:
            raise ValueError(f"Missing required field in match file: {e}")
        except Exception as e:
            raise ValueError(f"Failed to load match file: {e}")

