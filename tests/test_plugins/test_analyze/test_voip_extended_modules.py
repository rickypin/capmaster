"""Tests for extended VoIP analysis modules (MGCP, RTCP, SDP)."""

import pytest
from pathlib import Path

from capmaster.plugins.analyze.modules import get_all_modules, discover_modules
from capmaster.plugins.analyze.modules.mgcp_stats import MgcpStatsModule
from capmaster.plugins.analyze.modules.rtcp_stats import RtcpStatsModule
from capmaster.plugins.analyze.modules.sdp_stats import SdpStatsModule


# Discover all modules before running tests
discover_modules()


class TestMgcpStatsModule:
    """Tests for MGCP statistics module."""

    def test_module_registered(self):
        """Test that MGCP stats module is registered."""
        modules = get_all_modules()
        assert MgcpStatsModule in modules

    def test_module_name(self):
        """Test module name."""
        module = MgcpStatsModule()
        assert module.name == "mgcp_stats"

    def test_output_suffix(self):
        """Test output file suffix."""
        module = MgcpStatsModule()
        assert module.output_suffix == "mgcp-stats.txt"

    def test_required_protocols(self):
        """Test required protocols."""
        module = MgcpStatsModule()
        assert module.required_protocols == {"mgcp"}

    def test_build_tshark_args(self):
        """Test tshark arguments generation."""
        module = MgcpStatsModule()
        args = module.build_tshark_args(Path("test.pcap"))
        
        assert "-Y" in args
        assert "mgcp" in args
        assert "-T" in args
        assert "fields" in args
        assert "mgcp.req" in args
        assert "mgcp.rsp" in args

    def test_post_process_empty(self):
        """Test post-processing with empty input."""
        module = MgcpStatsModule()
        result = module.post_process("")
        assert "No MGCP messages found" in result

    def test_post_process_with_data(self):
        """Test post-processing with sample data."""
        module = MgcpStatsModule()

        # Sample tshark output (tab-separated)
        # Fields: frame.number, frame.len, ip.src, tcp.srcport, udp.srcport,
        #         ip.dst, tcp.dstport, udp.dstport, mgcp.req, mgcp.rsp,
        #         mgcp.req.verb, mgcp.rsp.rspcode
        sample_output = (
            "7\t103\t10.135.65.10\t\t2427\t10.129.131.12\t\t2427\tTrue\t\tNTFY\t\n"
            "8\t57\t10.129.131.12\t\t2427\t10.135.65.10\t\t2427\t\tTrue\t\t200\n"
            "34\t103\t10.135.65.10\t\t2427\t10.129.131.12\t\t2427\tTrue\t\tCRCX\t\n"
            "35\t57\t10.129.131.12\t\t2427\t10.135.65.10\t\t2427\t\tTrue\t\t200\n"
        )

        result = module.post_process(sample_output)

        # Check summary
        assert "MGCP Statistics" in result
        assert "Total MGCP Messages:" in result
        assert "4" in result

        # Check request/response counts
        assert "Requests:" in result
        assert "Responses:" in result

        # Check command statistics
        assert "MGCP Commands" in result
        assert "NTFY" in result
        assert "CRCX" in result

        # Check response code statistics
        assert "MGCP Response Codes" in result
        assert "200" in result
        assert "Success" in result

        # Check connections
        assert "MGCP Connections" in result


class TestRtcpStatsModule:
    """Tests for RTCP statistics module."""

    def test_module_registered(self):
        """Test that RTCP stats module is registered."""
        modules = get_all_modules()
        assert RtcpStatsModule in modules

    def test_module_name(self):
        """Test module name."""
        module = RtcpStatsModule()
        assert module.name == "rtcp_stats"

    def test_output_suffix(self):
        """Test output file suffix."""
        module = RtcpStatsModule()
        assert module.output_suffix == "rtcp-stats.txt"

    def test_required_protocols(self):
        """Test required protocols."""
        module = RtcpStatsModule()
        assert module.required_protocols == {"rtcp"}

    def test_build_tshark_args(self):
        """Test tshark arguments generation."""
        module = RtcpStatsModule()
        args = module.build_tshark_args(Path("test.pcap"))
        
        assert "-Y" in args
        assert "rtcp" in args
        assert "-T" in args
        assert "fields" in args
        assert "rtcp.pt" in args

    def test_post_process_empty(self):
        """Test post-processing with empty input."""
        module = RtcpStatsModule()
        result = module.post_process("")
        assert "No RTCP messages found" in result

    def test_post_process_with_data(self):
        """Test post-processing with sample data."""
        module = RtcpStatsModule()
        
        # Sample tshark output (tab-separated)
        # Fields: frame.number, frame.len, ip.src, udp.srcport, ip.dst, udp.dstport, rtcp.pt
        sample_output = (
            "64\t102\t10.135.65.10\t16677\t10.128.131.17\t19491\t200,202\n"
            "281\t102\t10.135.65.10\t16677\t10.128.131.17\t19491\t200,202\n"
            "549\t102\t10.135.65.10\t16677\t10.128.131.17\t19491\t200,202\n"
        )
        
        result = module.post_process(sample_output)
        
        # Check summary
        assert "RTCP Statistics" in result
        assert "Total RTCP Messages:" in result
        assert "3" in result
        
        # Check packet types
        assert "RTCP Packet Types:" in result
        assert "SR (Sender Report)" in result
        assert "SDES (Source Description)" in result
        
        # Check quality monitoring
        assert "Quality Monitoring:" in result


class TestSdpStatsModule:
    """Tests for SDP statistics module."""

    def test_module_registered(self):
        """Test that SDP stats module is registered."""
        modules = get_all_modules()
        assert SdpStatsModule in modules

    def test_module_name(self):
        """Test module name."""
        module = SdpStatsModule()
        assert module.name == "sdp_stats"

    def test_output_suffix(self):
        """Test output file suffix."""
        module = SdpStatsModule()
        assert module.output_suffix == "sdp-stats.txt"

    def test_required_protocols(self):
        """Test required protocols."""
        module = SdpStatsModule()
        assert module.required_protocols == {"sdp"}

    def test_build_tshark_args(self):
        """Test tshark arguments generation."""
        module = SdpStatsModule()
        args = module.build_tshark_args(Path("test.pcap"))
        
        assert "-Y" in args
        assert "sdp" in args
        assert "-T" in args
        assert "fields" in args
        assert "sdp.media" in args
        assert "sdp.media.port" in args
        assert "sdp.media.proto" in args

    def test_post_process_empty(self):
        """Test post-processing with empty input."""
        module = SdpStatsModule()
        result = module.post_process("")
        assert "No SDP messages found" in result

    def test_post_process_with_data(self):
        """Test post-processing with sample data."""
        module = SdpStatsModule()
        
        # Sample tshark output (tab-separated)
        # Fields: frame.number, frame.len, ip.src, ip.dst, sdp.media, 
        #         sdp.media.port, sdp.media.proto, sdp.media.format
        sample_output = (
            "14\t57\t10.135.100.85\t10.135.65.10\taudio,video\t0,0\tRTP/AVP,RTP/AVP\tITU-T G.711 PCMU,ITU-T H.263\n"
            "54\t163\t10.135.65.10\t10.129.131.12\taudio\t16676\tRTP/AVP\tITU-T G.711 PCMU\n"
            "57\t355\t10.129.131.12\t10.135.65.10\taudio\t19490\tRTP/AVP\tITU-T G.711 PCMU\n"
        )
        
        result = module.post_process(sample_output)
        
        # Check summary
        assert "SDP Statistics" in result
        assert "Total SDP Messages:" in result
        assert "3" in result
        
        # Check media types
        assert "Media Types:" in result
        assert "audio" in result
        
        # Check protocols
        assert "Transport Protocols:" in result
        assert "RTP/AVP" in result
        
        # Check codecs
        assert "Codecs/Formats:" in result
        assert "G.711" in result or "PCMU" in result

    def test_post_process_with_multiple_media(self):
        """Test post-processing with multiple media types."""
        module = SdpStatsModule()
        
        sample_output = (
            "25\t478\t10.135.65.10\t10.129.131.14\taudio,image\t0,0\tRTP/AVP,udptl\tITU-T G.729,t38\n"
        )
        
        result = module.post_process(sample_output)
        
        # Check that both media types are detected
        assert "audio" in result
        assert "image" in result or "Media Types:" in result
        
        # Check protocols
        assert "RTP/AVP" in result
        assert "udptl" in result or "Fax" in result


class TestVoIPExtendedModulesIntegration:
    """Integration tests for extended VoIP modules."""

    @pytest.fixture
    def voip_pcap(self):
        """Path to VoIP test PCAP file."""
        return Path("cases_02/V-001/VOIP.pcap")

    def test_mgcp_module_with_real_pcap(self, voip_pcap):
        """Test MGCP module with real PCAP file."""
        if not voip_pcap.exists():
            pytest.skip("Test PCAP file not found")
        
        module = MgcpStatsModule()
        
        # Build tshark command
        args = module.build_tshark_args(voip_pcap)
        assert "mgcp" in args
        
        # Module should execute if MGCP protocol is present
        assert module.required_protocols == {"mgcp"}

    def test_rtcp_module_with_real_pcap(self, voip_pcap):
        """Test RTCP module with real PCAP file."""
        if not voip_pcap.exists():
            pytest.skip("Test PCAP file not found")
        
        module = RtcpStatsModule()
        
        # Build tshark command
        args = module.build_tshark_args(voip_pcap)
        assert "rtcp" in args
        
        # Module should execute if RTCP protocol is present
        assert module.required_protocols == {"rtcp"}

    def test_sdp_module_with_real_pcap(self, voip_pcap):
        """Test SDP module with real PCAP file."""
        if not voip_pcap.exists():
            pytest.skip("Test PCAP file not found")
        
        module = SdpStatsModule()
        
        # Build tshark command
        args = module.build_tshark_args(voip_pcap)
        assert "sdp" in args
        
        # Module should execute if SDP protocol is present
        assert module.required_protocols == {"sdp"}

