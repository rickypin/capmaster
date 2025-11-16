"""Helpers for calling external PCAP tools (editcap / capinfos / tshark).

This module centralises external tool invocation for the preprocess plugin,
following the guidance in DESIGN_preprocess_and_config.md.  It currently
implements the minimal pieces needed for the ``archive-original`` and
``dedup`` steps and is designed to be extended later for time-align and
oneway support.
"""

from __future__ import annotations

from pathlib import Path
import logging
import os
import shutil
import subprocess
from typing import Final

from capmaster.utils.errors import CapMasterError

from .config import ToolsConfig

logger = logging.getLogger(__name__)


def _resolve_tool_path(
    explicit: Path | None,
    env_var: str,
    executable: str,
) -> str:
    """Resolve an external tool path with fallback order.

    Order (high → low):
    1. Explicit ``Path`` from ``ToolsConfig``.
    2. Environment variable (e.g. ``EDITCAP_PATH``).
    3. ``shutil.which(executable)``.

    Raises ``CapMasterError`` if the tool cannot be found.
    """

    if explicit is not None:
        return str(explicit)

    env_value = os.environ.get(env_var)
    if env_value:
        return env_value

    which = shutil.which(executable)
    if which is not None:
        return which

    raise CapMasterError(
        f"{executable} command not found",
        (
            f"Please install Wireshark tools and/or set {env_var} to the full path "
            f"of the {executable} binary."
        ),
    )


def get_editcap_path(tools: ToolsConfig) -> str:
    """Return the effective ``editcap`` executable path.

    This honours ``tools.editcap_path`` first, then ``EDITCAP_PATH``,
    and finally falls back to ``shutil.which("editcap")``.
    """

    return _resolve_tool_path(tools.editcap_path, "EDITCAP_PATH", "editcap")


def get_capinfos_path(tools: ToolsConfig) -> str:
    """Return the effective ``capinfos`` executable path.

    Currently unused in the initial implementation but provided so that
    time-align and reporting steps can reuse the same resolution logic.
    """

    return _resolve_tool_path(tools.capinfos_path, "CAPINFOS_PATH", "capinfos")




class TimeRange:
    """Simple container for first/last packet timestamps.

    Timestamps are represented as floating-point seconds since the Unix epoch
    (as typically produced by Wireshark tools when using machine-readable
    output modes).
    """

    def __init__(self, first_ts: float, last_ts: float) -> None:
        self.first_ts = first_ts
        self.last_ts = last_ts


def _parse_capinfos_time_range(output: str, input_file: Path) -> TimeRange:
    """Parse capinfos table output produced for ``-S`` time statistics.

    For Wireshark / capinfos 4.6.0 the machine-readable invocation::

        capinfos -T -m -Q -r -S <file>

    produces a single CSV line where fields 12 and 13 (0-based indices 11
    and 12) are the earliest and latest packet timestamps as seconds since
    the Unix epoch.

    If the output does not match this shape or the timestamp fields cannot
    be parsed, a ``CapMasterError`` is raised so that callers can fall back
    to an alternative method.
    """

    lines = [line for line in output.splitlines() if line.strip()]
    if not lines:
        raise CapMasterError(
            f"capinfos produced no output for {input_file}",
            "Ensure the file is a valid capture and capinfos is functional.",
        )

    # Table mode without header (-r) should give a single CSV line.
    # We intentionally look at the last non-empty line so that a stray
    # header or warning line earlier does not break parsing.
    line = lines[-1]
    parts = [p.strip().strip('"') for p in line.split(",")]
    if len(parts) < 13:
        raise CapMasterError(
            f"Unexpected capinfos output format for {input_file}: {line!r}",
            "This parser expects Wireshark/capinfos 4.6.0 -S table output.",
        )

    try:
        # Wireshark 4.6.0: earliest/latest timestamps in seconds since epoch.
        first_ts = float(parts[11])
        last_ts = float(parts[12])
    except ValueError as exc:
        raise CapMasterError(
            f"Failed to parse capinfos timestamps for {input_file}",
            f"Offending values: {parts[11:13]}",
        ) from exc

    return TimeRange(first_ts, last_ts)


def get_time_range_capinfos(*, tools: ToolsConfig, input_file: Path, timeout: int | None = None) -> TimeRange:
    """Obtain first/last packet timestamps using ``capinfos``.

    This prefers the lightweight metadata path described in the design
    document. Callers may catch ``CapMasterError`` and fall back to tshark
    when capinfos is unavailable or its output cannot be parsed.
    """

    capinfos_path = get_capinfos_path(tools)
    cmd = [
        capinfos_path,
        "-T",  # table output
        "-m",  # comma-separated
        "-Q",  # double-quoted fields
        "-r",  # no header line
        "-S",  # earliest/latest timestamps in seconds since epoch
        str(input_file),
    ]

    logger.debug("Running capinfos for time range: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:  # pragma: no cover - environment specific
        raise CapMasterError(
            "capinfos executable not found",
            "Please ensure Wireshark is installed and CAPINFOS_PATH is configured.",
        ) from exc
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - rare
        raise CapMasterError(
            f"capinfos timed out while processing {input_file}",
            "Consider increasing the timeout or using smaller PCAP files.",
        ) from exc

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        msg = f"capinfos failed for {input_file} with exit code {result.returncode}"
        if stderr:
            msg += f": {stderr}"
        raise CapMasterError(
            msg,
            "Please verify that the capture file is valid and that capinfos supports the requested options.",
        )

    return _parse_capinfos_time_range(result.stdout, input_file)



def run_editcap_time_crop(
    *,
    tools: ToolsConfig,
    input_file: Path,
    output_file: Path,
    start_time: float,
    end_time: float,
    timeout: int | None = None,
) -> None:
    """Run ``editcap`` to crop a PCAP file to a time window.

    The time window is expressed in seconds since the Unix epoch and mapped to
    editcap's ``-A``/``-B`` options. The function creates parent directories
    for ``output_file`` as needed and raises ``CapMasterError`` on failure.
    """

    if end_time <= start_time:
        raise CapMasterError(
            "Invalid time window for editcap crop",
            f"Start {start_time} must be earlier than end {end_time}.",
        )

    editcap_path = get_editcap_path(tools)

    output_file.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        editcap_path,
        "-A",
        str(start_time),
        "-B",
        str(end_time),
        str(input_file),
        str(output_file),
    ]

    logger.debug("Running editcap time crop: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:  # pragma: no cover - environment specific
        raise CapMasterError(
            "editcap executable not found",
            "Please ensure Wireshark is installed and EDITCAP_PATH is configured.",
        ) from exc
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - rare
        raise CapMasterError(
            f"editcap timed out while processing {input_file}",
            "Consider increasing the timeout or using smaller PCAP files.",
        ) from exc

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        msg = f"editcap failed for {input_file} with exit code {result.returncode}"
        if stderr:
            msg += f": {stderr}"
        raise CapMasterError(
            msg,
            "Please verify that the PCAP file is valid and that editcap supports the given options.",
        )

    logger.debug("editcap time crop completed for %s -> %s", input_file, output_file)


def run_editcap_time_crop_and_dedup(
    *,
    tools: ToolsConfig,
    input_file: Path,
    output_file: Path,
    start_time: float,
    end_time: float,
    window_packets: int | None,
    ignore_bytes: int,
    timeout: int | None = None,
) -> None:
    """Run ``editcap`` once to crop and deduplicate a PCAP file.

    This combines time alignment (``-A``/``-B``) with duplicate removal
    (``-d``/``-D``/``-I``) so that large captures are only scanned once.
    """

    if end_time <= start_time:
        raise CapMasterError(
            "Invalid time window for editcap crop+dedup",
            f"Start {start_time} must be earlier than end {end_time}.",
        )

    editcap_path = get_editcap_path(tools)

    output_file.parent.mkdir(parents=True, exist_ok=True)

    cmd: list[str] = [
        editcap_path,
        "-A",
        str(start_time),
        "-B",
        str(end_time),
    ]

    # Duplicate removal options mirror :func:`run_editcap_dedup`.
    if window_packets is None:
        # Use editcap's default duplicate removal behaviour.
        cmd.append("-d")
    else:
        cmd.extend(["-D", str(window_packets)])

    if ignore_bytes > 0:
        cmd.extend(["-I", str(ignore_bytes)])

    cmd.extend([str(input_file), str(output_file)])

    logger.debug("Running editcap time crop+dedup: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:  # pragma: no cover - environment specific
        raise CapMasterError(
            "editcap executable not found",
            "Please ensure Wireshark is installed and EDITCAP_PATH is configured.",
        ) from exc
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - rare
        raise CapMasterError(
            f"editcap timed out while processing {input_file}",
            "Consider increasing the timeout or using smaller PCAP files.",
        ) from exc

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        msg = f"editcap failed for {input_file} with exit code {result.returncode}"
        if stderr:
            msg += f": {stderr}"
        raise CapMasterError(
            msg,
            "Please verify that the PCAP file is valid and that editcap supports the given options.",
        )

    logger.debug("editcap time crop+dedup completed for %s -> %s", input_file, output_file)



def get_time_range_tshark(*, input_file: Path, timeout: int | None = None) -> TimeRange:
    """Fallback: obtain first/last timestamps using ``tshark``.

    This uses :class:`capmaster.core.tshark_wrapper.TsharkWrapper` to extract
    ``frame.time_epoch`` values and derives the minimum/maximum.

    It is less efficient than ``capinfos`` because it may need to scan the
    entire capture, but it keeps the behaviour correct in environments where
    capinfos is unavailable.
    """

    from capmaster.core.tshark_wrapper import TsharkWrapper  # local import to avoid cycles

    tshark = TsharkWrapper()
    args = [
        "-T",
        "fields",
        "-e",
        "frame.time_epoch",
    ]

    logger.debug("Running tshark for time range on %s", input_file)
    result = tshark.execute(args=args, input_file=input_file, timeout=timeout)

    lines = [line for line in (result.stdout or "").splitlines() if line.strip()]
    if not lines:
        raise CapMasterError(
            f"tshark produced no frame timestamps for {input_file}",
            "Ensure the file contains packets and tshark is functional.",
        )

    try:
        values = [float(line.strip()) for line in lines]
    except ValueError as exc:
        raise CapMasterError(
            f"Failed to parse tshark timestamps for {input_file}",
            "Unexpected frame.time_epoch output format.",
        ) from exc

    return TimeRange(min(values), max(values))


def get_time_range(*, tools: ToolsConfig, input_file: Path, timeout: int | None = None) -> TimeRange:
    """Get first/last timestamps, preferring capinfos and falling back to tshark."""

    try:
        return get_time_range_capinfos(tools=tools, input_file=input_file, timeout=timeout)
    except CapMasterError as exc:
        logger.warning("capinfos time range failed for %s: %s; falling back to tshark", input_file, exc)
        return get_time_range_tshark(input_file=input_file, timeout=timeout)


_EDITCAP_DEDUP_DEFAULT_WINDOW: Final[int] = 5


def get_packet_count(*, tools: ToolsConfig, input_file: Path, timeout: int | None = None) -> int:
    """Return the packet count of a capture file using ``capinfos``.

    This is used by the preprocess report generation and some tests to
    compare before/after behaviour. Failures are reported via
    :class:`CapMasterError` so that callers can decide whether to treat
    them as fatal or degrade gracefully.
    """

    capinfos_path = get_capinfos_path(tools)
    cmd = [
        capinfos_path,
        "-c",  # only show packet count
        str(input_file),
    ]

    logger.debug("Running capinfos for packet count: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:  # pragma: no cover - environment specific
        raise CapMasterError(
            "capinfos executable not found",
            "Please ensure Wireshark is installed and CAPINFOS_PATH is configured.",
        ) from exc
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - rare
        raise CapMasterError(
            f"capinfos timed out while processing {input_file}",
            "Consider increasing the timeout or using smaller PCAP files.",
        ) from exc

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        msg = f"capinfos failed for {input_file} with exit code {result.returncode}"
        if stderr:
            msg += f": {stderr}"
        raise CapMasterError(
            msg,
            "Please verify that the capture file is valid and that capinfos supports the given options.",
        )

    # Wireshark 4.6.0 typically prints a line such as:
    #   Number of packets: 12,345
    # or:
    #   Number of packets: 156 k
    for line in (result.stdout or "").splitlines():
        if "Number of packets" not in line:
            continue

        _, _, value = line.partition(":")
        raw = value.strip().replace(",", "")
        if not raw:
            continue

        # Split on whitespace to handle both "156 k" and "156" forms.
        tokens = raw.split()
        num_token = tokens[0]
        suffix_token = tokens[1] if len(tokens) > 1 else ""

        # Derive an SI unit suffix (k/M/G) from either a separate token or
        # the last character of the numeric token (e.g. "156k").
        suffix_char = ""
        if suffix_token:
            suffix_char = suffix_token[0].lower()
        elif num_token and not num_token[-1].isdigit():
            suffix_char = num_token[-1].lower()
            num_token = num_token[:-1]

        multiplier = 1
        if suffix_char == "k":
            multiplier = 1_000
        elif suffix_char == "m":
            multiplier = 1_000_000
        elif suffix_char == "g":
            multiplier = 1_000_000_000

        try:
            base = float(num_token)
            return int(base * multiplier)
        except ValueError as exc:  # pragma: no cover - unexpected format
            raise CapMasterError(
                f"Failed to parse packet count from capinfos output for {input_file}",
                f"Offending line: {line!r}",
            ) from exc

    raise CapMasterError(
        f"capinfos output for {input_file} did not contain a packet count line",
        "Check the capinfos version or use tshark-based counting as a fallback.",
    )


def run_editcap_dedup(
    *,
    tools: ToolsConfig,
    input_file: Path,
    output_file: Path,
    window_packets: int | None,
    ignore_bytes: int,
    timeout: int | None = None,
) -> None:
    """Run ``editcap`` to deduplicate packets in a single PCAP file.

    Args:
        tools: Tools configuration (for locating ``editcap``).
        input_file: Source PCAP/PCAPNG file.
        output_file: Destination file for deduplicated traffic.
        window_packets: Size of the deduplication window.  ``None`` means
            use ``editcap -d`` (its built-in default window, typically
            equivalent to ``-D 5``).
        ignore_bytes: Number of bytes at the end of each packet to ignore
            when computing fingerprints (mapped to ``editcap -I N``).
        timeout: Optional timeout for the editcap process in seconds.

    Raises:
        CapMasterError: If ``editcap`` is not available or the command fails.
    """

    editcap_path = get_editcap_path(tools)

    output_file.parent.mkdir(parents=True, exist_ok=True)

    cmd: list[str] = [editcap_path]

    if window_packets is None:
        # Use editcap's default duplicate removal behaviour.
        cmd.append("-d")
    else:
        cmd.extend(["-D", str(window_packets)])

    if ignore_bytes > 0:
        cmd.extend(["-I", str(ignore_bytes)])

    cmd.extend([str(input_file), str(output_file)])

    logger.debug("Running editcap dedup: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:  # pragma: no cover - environment specific
        raise CapMasterError(
            "editcap executable not found",
            "Please ensure Wireshark is installed and EDITCAP_PATH is configured.",
        ) from exc
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - rare
        raise CapMasterError(
            f"editcap timed out while processing {input_file}",
            "Consider increasing the timeout or using smaller PCAP files.",
        ) from exc

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        msg = f"editcap failed for {input_file} with exit code {result.returncode}"
        if stderr:
            msg += f": {stderr}"
        raise CapMasterError(
            msg,
            "Please verify that the PCAP file is valid and that editcap supports the given options.",
        )

    logger.debug("editcap dedup completed for %s -> %s", input_file, output_file)

