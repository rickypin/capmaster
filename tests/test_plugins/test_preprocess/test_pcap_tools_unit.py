from pathlib import Path

import pytest

from capmaster.plugins.preprocess.pcap_tools import (
    TimeRange,
    _parse_capinfos_time_range,
    get_packet_count,
    get_time_range,
)
from capmaster.plugins.preprocess.config import ToolsConfig
from capmaster.utils.errors import CapMasterError


def test_parse_capinfos_time_range_wireshark_460() -> None:
    """_parse_capinfos_time_range matches Wireshark 4.6.0 -S table output."""

    # Single CSV line as produced by:
    #   capinfos -T -m -Q -r -S <file>
    output = (
        '"tests/foo.pcap","pcap","linux-sll","microseconds","262144","n/a","n/a",'
        '"156267","155659085","150658517","206.813594",'
        '"1714456808.811090","1714457015.624684",'
        '"728474.92","5827799.38","964.11","755.59",'
        '"hash1","hash2","False","","","",""\n'
    )

    tr = _parse_capinfos_time_range(output, Path("tests/foo.pcap"))
    assert isinstance(tr, TimeRange)
    assert tr.first_ts == pytest.approx(1714456808.811090)
    assert tr.last_ts == pytest.approx(1714457015.624684)


def test_get_packet_count_parses_k_suffix(monkeypatch) -> None:
    """get_packet_count should handle Wireshark 4.6.0 '156 k' style output."""

    def fake_run(*args, **kwargs):
        class Result:
            def __init__(self) -> None:
                self.stdout = "Number of packets:   156 k\n"
                self.stderr = ""
                self.returncode = 0

        return Result()

    monkeypatch.setattr(
        "capmaster.plugins.preprocess.pcap_tools.subprocess.run",
        fake_run,
    )

    tools = ToolsConfig()
    count = get_packet_count(tools=tools, input_file=Path("tests/foo.pcap"))

    # 156 k should be interpreted as approximately 156,000 packets.
    assert count == 156_000




def test_get_time_range_falls_back_to_tshark_when_capinfos_fails(monkeypatch) -> None:
    """get_time_range should fall back to tshark if capinfos fails with CapMasterError."""

    tools = ToolsConfig()

    def fake_capinfos(*, tools: ToolsConfig, input_file: Path, timeout: float | None = None):
        raise CapMasterError("capinfos failed", "hint")

    def fake_tshark(*, input_file: Path, timeout: float | None = None, **_):
        return TimeRange(first_ts=1.0, last_ts=2.0)

    monkeypatch.setattr(
        "capmaster.plugins.preprocess.pcap_tools.get_time_range_capinfos",
        fake_capinfos,
    )
    monkeypatch.setattr(
        "capmaster.plugins.preprocess.pcap_tools.get_time_range_tshark",
        fake_tshark,
    )

    tr = get_time_range(tools=tools, input_file=Path("tests/foo.pcap"))
    assert isinstance(tr, TimeRange)
    assert tr.first_ts == pytest.approx(1.0)
    assert tr.last_ts == pytest.approx(2.0)



def test_get_packet_count_raises_capmastererror_on_failure(monkeypatch) -> None:
    """get_packet_count should raise CapMasterError when capinfos returns non-zero exit code."""

    def fake_run(*args, **kwargs):
        class Result:
            def __init__(self) -> None:
                self.stdout = ""
                self.stderr = "capinfos failed badly"
                self.returncode = 1

        return Result()

    monkeypatch.setattr(
        "capmaster.plugins.preprocess.pcap_tools.subprocess.run",
        fake_run,
    )

    tools = ToolsConfig()
    with pytest.raises(CapMasterError) as excinfo:
        get_packet_count(tools=tools, input_file=Path("tests/foo.pcap"))

    # Error message should mention the exit code to help with debugging.
    assert "exit code 1" in str(excinfo.value)
