"""Streamdiff plugin: per-connection A-only packet detection between two PCAPs."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import click

from capmaster.plugins import register_plugin
from capmaster.plugins.base import PluginBase
from capmaster.plugins.compare.packet_comparator import ComparisonResult, DiffType, PacketComparator, PacketDiff
from capmaster.plugins.compare.packet_extractor import PacketExtractor
from capmaster.plugins.match.quality_analyzer import ConnectionPair, parse_matched_connections
from capmaster.utils.cli_options import dual_file_input_options
from capmaster.utils.input_parser import DualFileInputParser
from capmaster.utils.errors import CapMasterError, InsufficientFilesError, handle_error

logger = logging.getLogger(__name__)


def _select_pair_by_index(pairs: list[ConnectionPair], pair_index: int) -> ConnectionPair:
    """Select a connection pair by 1-based index with validation.

    Raises CapMasterError on out-of-range index.
    """
    if pair_index < 1 or pair_index > len(pairs):
        raise CapMasterError(
            f"Pair index {pair_index} is out of range. Valid range is 1-{len(pairs)}."
        )
    return pairs[pair_index - 1]


@register_plugin
class StreamDiffPlugin(PluginBase):
    """Expose per-stream A-only packet detection as a CLI command."""

    @property
    def name(self) -> str:
        """CLI subcommand name."""
        return "streamdiff"

    def setup_cli(self, cli_group: click.Group) -> None:
        """Register the streamdiff CLI command."""

        @cli_group.command(name=self.name)
        @dual_file_input_options
        @click.option(
            "--matched-connections",
            type=click.Path(exists=True, dir_okay=False, path_type=Path),
            help=(
                "Matched connections text file produced by 'capmaster match -o ...'. "
                "If provided, use --pair-index to choose a connection pair."
            ),
        )
        @click.option(
            "--pair-index",
            type=int,
            default=None,
            help=(
                "1-based index of the connection pair in matched-connections file "
                "to analyze. Required when --matched-connections is used."
            ),
        )
        @click.option(
            "--file1-stream-id",
            type=int,
            default=None,
            help=(
                "tcp.stream id in file1 to use when not using matched-connections. "
                "Must be provided together with --file2-stream-id."
            ),
        )
        @click.option(
            "--file2-stream-id",
            type=int,
            default=None,
            help=(
                "tcp.stream id in file2 to use when not using matched-connections. "
                "Must be provided together with --file1-stream-id."
            ),
        )
        @click.option(
            "-o",
            "--output",
            "output_file",
            type=click.Path(path_type=Path),
            help="Output file for the streamdiff report (default: stdout).",
        )
        @click.pass_context
        def streamdiff_command(
            ctx: click.Context,
            input_path: Optional[str],
            file1: Optional[Path],
            file1_pcapid: Optional[int],
            file2: Optional[Path],
            file2_pcapid: Optional[int],
            matched_connections: Optional[Path],
            pair_index: Optional[int],
            file1_stream_id: Optional[int],
            file2_stream_id: Optional[int],
            output_file: Optional[Path],
        ) -> None:
            """Compare a single TCP connection between two captures and list
            packets that are present only in A or only in B.

            There are two ways to select the connection pair:

            1) From a matched-connections file:

               capmaster streamdiff -i /path/to/2pcaps \
                 --matched-connections matched_connections.txt \
                 --pair-index 1

            2) By explicit tcp.stream IDs:

               capmaster streamdiff -i /path/to/2pcaps \
                 --file1-stream-id 7 --file2-stream-id 33
            """

            exit_code = self.execute(
                input_path=input_path,
                file1=file1,
                file1_pcapid=file1_pcapid,
                file2=file2,
                file2_pcapid=file2_pcapid,
                matched_connections=matched_connections,
                pair_index=pair_index,
                file1_stream_id=file1_stream_id,
                file2_stream_id=file2_stream_id,
                output_file=output_file,
            )
            ctx.exit(exit_code)

    def execute(  # type: ignore[override]
        self,
        input_path: str | Path | None = None,
        file1: Path | None = None,
        file1_pcapid: int | None = None,
        file2: Path | None = None,
        file2_pcapid: int | None = None,
        matched_connections: Path | None = None,
        pair_index: int | None = None,
        file1_stream_id: int | None = None,
        file2_stream_id: int | None = None,
        output_file: Path | None = None,
    ) -> int:
        """Execute the streamdiff plugin.

        Focus on human-readable reporting of packets that exist in capture A but
        are missing in capture B for a single TCP connection. Also reports
        packets that exist in capture B but are missing in capture A.
        """
        try:
            dual_input = DualFileInputParser.parse(
                input_path=input_path,
                file1=file1,
                file2=file2,
                file1_pcapid=file1_pcapid,
                file2_pcapid=file2_pcapid,
            )
        except InsufficientFilesError as exc:
            return handle_error(exc, show_traceback=False)

        file_a = dual_input.file1
        file_b = dual_input.file2
        pcap_id_mapping = dual_input.pcap_id_mapping

        try:
            stream_id_a, stream_id_b, conn_label = self._resolve_stream_ids(
                file_a=file_a,
                file_b=file_b,
                pcap_id_mapping=pcap_id_mapping,
                matched_connections=matched_connections,
                pair_index=pair_index,
                file1_stream_id=file1_stream_id,
                file2_stream_id=file2_stream_id,
            )
        except CapMasterError as exc:
            return handle_error(exc, show_traceback=False)

        logger.info(
            "Running streamdiff for %s: file_a=%s(stream=%s), file_b=%s(stream=%s)",
            conn_label,
            file_a.name,
            stream_id_a,
            file_b.name,
            stream_id_b,
        )

        extractor = PacketExtractor()
        comparator = PacketComparator()

        packets_a = extractor.extract_by_stream_id(file_a, stream_id_a)
        packets_b = extractor.extract_by_stream_id(file_b, stream_id_b)

        connection_id = conn_label or f"stream {stream_id_a} vs {stream_id_b}"
        result = comparator.compare(packets_a, packets_b, connection_id, matched_only=False)

        # Filter for A-only and B-only packets
        a_only_diffs = [
            d for d in result.differences
            if d.diff_type == DiffType.IP_ID and d.value_b == "MISSING"
        ]
        b_only_diffs = [
            d for d in result.differences
            if d.diff_type == DiffType.IP_ID and d.value_a == "MISSING"
        ]

        # Generate streamdiff specific report
        streamdiff_report = self._build_report(
            file_a=file_a,
            file_b=file_b,
            stream_id_a=stream_id_a,
            stream_id_b=stream_id_b,
            result=result,
            a_only_diffs=a_only_diffs,
            b_only_diffs=b_only_diffs,
        )

        # Generate flow comparison report
        flow_report = comparator.format_flow_comparison(
            packets_a=packets_a,
            packets_b=packets_b,
            result=result,
        )

        # Combine reports
        full_report = f"{streamdiff_report}\n\n{flow_report}"

        if output_file:
            output_file.write_text(full_report)
        else:
            click.echo(full_report)

        return 0

    def _resolve_stream_ids(
        self,
        file_a: Path,
        file_b: Path,
        pcap_id_mapping: dict[str, int] | None,
        matched_connections: Path | None,
        pair_index: int | None,
        file1_stream_id: int | None,
        file2_stream_id: int | None,
    ) -> tuple[int, int, str]:
        """Resolve stream IDs for A/B either from matched-connections or CLI IDs.

        Returns (stream_id_a, stream_id_b, connection_label).
        """
        # Case 1: use matched-connections file
        if matched_connections is not None:
            if pair_index is None:
                raise CapMasterError(
                    "--pair-index is required when --matched-connections is provided."
                )

            pairs = parse_matched_connections(matched_connections)
            if not pairs:
                raise CapMasterError(
                    "No valid connection pairs found in matched connections file."
                )

            pair = _select_pair_by_index(pairs, pair_index)

            # Map pcap IDs from matched file back to our local file_a/file_b
            if pcap_id_mapping is None:
                # Fallback: assume file_a is PCAPID 0 and file_b is 1
                id_a, id_b = 0, 1
            else:
                id_a = pcap_id_mapping.get(str(file_a), 0)
                id_b = pcap_id_mapping.get(str(file_b), 1)

            # By convention in match output, stream_a belongs to PCAPID 0, stream_b to 1
            # We need to align those to our local A/B ordering.
            stream_a = pair.stream_a
            stream_b = pair.stream_b

            if id_a == 0 and id_b == 1:
                stream_id_a = stream_a
                stream_id_b = stream_b
            elif id_a == 1 and id_b == 0:
                stream_id_a = stream_b
                stream_id_b = stream_a
            else:
                raise CapMasterError(
                    "Unexpected PCAP ID mapping; expected exactly two PCAP IDs 0/1."
                )

            conn_label = (
                f"{pair.connection_a} (PCAPID={id_a}, stream={stream_id_a}) vs "
                f"{pair.connection_b} (PCAPID={id_b}, stream={stream_id_b})"
            )
            return stream_id_a, stream_id_b, conn_label

        # Case 2: explicit stream IDs on CLI
        if (file1_stream_id is None) ^ (file2_stream_id is None):
            raise CapMasterError(
                "Both --file1-stream-id and --file2-stream-id must be provided together "
                "when not using --matched-connections."
            )

        if file1_stream_id is None or file2_stream_id is None:
            raise CapMasterError(
                "Must provide either --matched-connections/--pair-index or both "
                "--file1-stream-id and --file2-stream-id."
            )

        conn_label = (
            f"{file_a.name}(stream={file1_stream_id}) vs "
            f"{file_b.name}(stream={file2_stream_id})"
        )
        return file1_stream_id, file2_stream_id, conn_label

    def _build_report(
        self,
        file_a: Path,
        file_b: Path,
        stream_id_a: int,
        stream_id_b: int,
        result: "ComparisonResult",
        a_only_diffs: list["PacketDiff"],
        b_only_diffs: list["PacketDiff"],
    ) -> str:
        """Build a human-readable text report for A-only and B-only packets.

        The report is optimized for terminal viewing and Markdown rendering.
        """
        # We know at call sites that result is actually a ComparisonResult.
        assert hasattr(result, "packets_a") and hasattr(result, "packets_b")

        header_lines: list[str] = []
        header_lines.append("# streamdiff report: A-only/B-only packets")
        header_lines.append("")
        header_lines.append(
            f"Capture A: {file_a.name} (stream {stream_id_a})\n"
            f"Capture B: {file_b.name} (stream {stream_id_b})"
        )
        header_lines.append("")

        summary_lines: list[str] = []
        summary_lines.append("```text")
        summary_lines.append("Summary:")
        summary_lines.append(f"  Packets in A: {result.packets_a}")  # type: ignore[attr-defined]
        summary_lines.append(f"  Packets in B: {result.packets_b}")  # type: ignore[attr-defined]
        summary_lines.append(f"  A-only packets (by IP ID): {len(a_only_diffs)}")
        summary_lines.append(f"  B-only packets (by IP ID): {len(b_only_diffs)}")
        summary_lines.append("")

        if not a_only_diffs and not b_only_diffs:
            summary_lines.append("No A-only or B-only packets detected.")
            summary_lines.append("```")
            return "\n".join(header_lines + [""] + summary_lines)

        # A-only table (if any)
        if a_only_diffs:
            summary_lines.append("A-only packet details:")
            summary_lines.append(f"  {'IPID':<8} {'Frame A':<10}")
            summary_lines.append(f"  {'-'*8} {'-'*10}")

            for diff in a_only_diffs:
                # For A-only IP_ID diffs, value_a stores the hex IPID string,
                # frame_a is the frame number.
                ipid = getattr(diff, "value_a", "?")
                frame_a = getattr(diff, "frame_a", -1)
                summary_lines.append(f"  {ipid:<8} {str(frame_a):<10}")

            summary_lines.append("")

        # B-only table (if any)
        if b_only_diffs:
            summary_lines.append("B-only packet details:")
            summary_lines.append(f"  {'IPID':<8} {'Frame B':<10}")
            summary_lines.append(f"  {'-'*8} {'-'*10}")

            for diff in b_only_diffs:
                # For B-only IP_ID diffs, value_b stores the hex IPID string,
                # frame_b is the frame number.
                ipid = getattr(diff, "value_b", "?")
                frame_b = getattr(diff, "frame_b", -1)
                summary_lines.append(f"  {ipid:<8} {str(frame_b):<10}")

        summary_lines.append("```")

        return "\n".join(header_lines + [""] + summary_lines)

