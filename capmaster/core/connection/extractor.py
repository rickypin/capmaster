"""TCP field extraction from PCAP files."""

from __future__ import annotations
import csv
from collections.abc import Iterator
from pathlib import Path

from capmaster.core.tshark_wrapper import TsharkWrapper
from capmaster.core.connection.models import TcpPacket


class TcpFieldExtractor:
    """
    Extract TCP fields from PCAP files using tshark.

    This class uses tshark to extract relevant TCP fields needed for
    connection matching, including frame number, stream ID, IP addresses,
    ports, flags, sequence numbers, options, and payload length.
    """

    # Fields to extract from tshark
    FIELDS = [
        "frame.number",
        "frame.time_epoch",
        "tcp.stream",
        "ip.proto",  # IP protocol number (6=TCP, 17=UDP, etc.)
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.flags",
        "tcp.seq",
        "tcp.ack",
        "tcp.options",
        "tcp.len",
        "ip.id",
        "tcp.options.timestamp.tsval",  # TCP timestamp TSval
        "tcp.options.timestamp.tsecr",  # TCP timestamp TSecr
        "data.data",  # Payload data (hex)
        "ip.ttl",  # IP Time To Live
        "frame.len",  # Frame length (total packet size)
    ]

    def __init__(self) -> None:
        """Initialize the extractor with a tshark wrapper."""
        self.tshark = TsharkWrapper()

    def extract(self, pcap_file: Path) -> Iterator[TcpPacket]:
        """
        Extract TCP packets from a PCAP file.

        Args:
            pcap_file: Path to the PCAP file

        Yields:
            TcpPacket objects for each TCP packet in the file

        Raises:
            RuntimeError: If tshark extraction fails
        """
        # Build tshark command
        args = [
            "-r",
            str(pcap_file),
            "-Y",
            "tcp",  # Filter for TCP packets only
            # NOTE: Use relative sequence numbers to match original script behavior
            # Original script uses tcp.seq which defaults to relative sequence numbers
            # This means SYN packets have seq=0, making ISN matching work correctly
            "-o",
            "tcp.desegment_tcp_streams:false",  # Disable TCP reassembly
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "quote=d",
            "-E",
            "occurrence=f",  # First occurrence only
        ]

        # Add field extraction arguments
        for field in self.FIELDS:
            args.extend(["-e", field])

        # OPTIMIZATION: Use pipe to read tshark output directly
        # This avoids temporary file I/O overhead
        result = self.tshark.execute(args)

        if result.returncode != 0:
            raise RuntimeError(f"tshark extraction failed: {result.stderr}")

        # Parse the TSV output from stdout
        yield from self._parse_tsv_string(result.stdout)

    def _parse_tsv_string(self, tsv_content: str) -> Iterator[TcpPacket]:
        """
        Parse TSV output from tshark (from string).

        Args:
            tsv_content: TSV content as string

        Yields:
            TcpPacket objects
        """
        # Split into lines and parse as CSV
        lines = tsv_content.strip().split('\n')
        reader = csv.reader(lines, delimiter="\t")

        for row in reader:
            if len(row) < len(self.FIELDS):
                # Skip incomplete rows
                continue

            try:
                packet = self._parse_row(row)
                if packet:
                    yield packet
            except (ValueError, IndexError):
                # Skip malformed rows
                continue

    def _parse_tsv(self, tsv_file: Path) -> Iterator[TcpPacket]:
        """
        Parse TSV output from tshark (from file).

        Args:
            tsv_file: Path to the TSV file

        Yields:
            TcpPacket objects

        Note:
            This method is kept for backward compatibility but is no longer
            used by the extract() method which now uses _parse_tsv_string().
        """
        with open(tsv_file, encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f, delimiter="\t")

            for row in reader:
                if len(row) < len(self.FIELDS):
                    # Skip incomplete rows
                    continue

                try:
                    packet = self._parse_row(row)
                    if packet:
                        yield packet
                except (ValueError, IndexError):
                    # Skip malformed rows
                    continue

    def _parse_row(self, row: list[str]) -> TcpPacket | None:
        """
        Parse a single TSV row into a TcpPacket.

        Args:
            row: List of field values from TSV

        Returns:
            TcpPacket object or None if parsing fails
        """
        try:
            # Extract fields (in the same order as FIELDS)
            frame_number = int(row[0]) if row[0] else 0
            timestamp = float(row[1]) if row[1] else 0.0
            stream_id = int(row[2]) if row[2] else 0
            protocol = int(row[3]) if row[3] else 6  # Default to TCP (6)
            src_ip = row[4] or ""
            dst_ip = row[5] or ""
            src_port = int(row[6]) if row[6] else 0
            dst_port = int(row[7]) if row[7] else 0
            flags = row[8] or "0x0000"
            seq = int(row[9]) if row[9] else 0
            ack = int(row[10]) if row[10] else 0
            options = row[11] or ""
            length = int(row[12]) if row[12] else 0
            ip_id = int(row[13], 16) if row[13] else 0  # IP ID is in hex
            tcp_timestamp_tsval = row[14] if len(row) > 14 else ""
            tcp_timestamp_tsecr = row[15] if len(row) > 15 else ""
            payload_data = row[16] if len(row) > 16 else ""
            ttl = int(row[17]) if len(row) > 17 and row[17] else 0
            frame_len = int(row[18]) if len(row) > 18 and row[18] else 0

            return TcpPacket(
                frame_number=frame_number,
                stream_id=stream_id,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                flags=flags,
                seq=seq,
                ack=ack,
                options=options,
                length=length,
                ip_id=ip_id,
                timestamp=timestamp,
                tcp_timestamp_tsval=tcp_timestamp_tsval,
                tcp_timestamp_tsecr=tcp_timestamp_tsecr,
                payload_data=payload_data,
                ttl=ttl,
                frame_len=frame_len,
            )
        except (ValueError, IndexError):
            return None

    def extract_to_file(self, pcap_file: Path, output_file: Path) -> None:
        """
        Extract TCP fields and save to a TSV file.

        Args:
            pcap_file: Path to the PCAP file
            output_file: Path to the output TSV file
        """
        # Build tshark command
        args = [
            "-r",
            str(pcap_file),
            "-Y",
            "tcp",
            "-o",
            "tcp.relative_sequence_numbers:false",  # Use absolute sequence numbers
            "-o",
            "tcp.desegment_tcp_streams:false",  # Disable TCP reassembly
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "quote=d",
            "-E",
            "occurrence=f",
        ]

        # Add field extraction arguments
        for field in self.FIELDS:
            args.extend(["-e", field])

        # Execute tshark
        result = self.tshark.execute(args, output_file=output_file)

        if result.returncode != 0:
            raise RuntimeError(f"tshark extraction failed: {result.stderr}")
