"""Tests for VoIP and SSH analysis modules."""

from pathlib import Path

import pytest

from capmaster.plugins.analyze.modules.sip_stats import SipStatsModule
from capmaster.plugins.analyze.modules.rtp_stats import RtpStatsModule
from capmaster.plugins.analyze.modules.ssh_stats import SshStatsModule


class TestSipStatsModule:
    """Tests for SIP statistics module."""

    @pytest.fixture
    def module(self) -> SipStatsModule:
        """Create a SipStatsModule instance."""
        return SipStatsModule()

    def test_module_name(self, module: SipStatsModule):
        """Test that module has correct name."""
        assert module.name == "sip_stats"

    def test_output_suffix(self, module: SipStatsModule):
        """Test that module has correct output suffix."""
        assert module.output_suffix == "sip-stats.txt"

    def test_required_protocols(self, module: SipStatsModule):
        """Test that module requires SIP protocol."""
        assert module.required_protocols == {"sip"}

    def test_should_execute_with_sip(self, module: SipStatsModule):
        """Test that module executes when SIP is detected."""
        assert module.should_execute({"sip"}) is True
        assert module.should_execute({"sip", "rtp"}) is True

    def test_should_not_execute_without_sip(self, module: SipStatsModule):
        """Test that module does not execute without SIP."""
        assert module.should_execute({"http"}) is False
        assert module.should_execute(set()) is False

    def test_build_tshark_args(self, module: SipStatsModule):
        """Test tshark arguments generation."""
        args = module.build_tshark_args(Path("test.pcap"))
        assert isinstance(args, list)
        assert "-Y" in args
        assert "sip" in args
        assert "-T" in args
        assert "fields" in args
        assert "-e" in args
        assert "sip.Method" in args
        assert "sip.Status-Code" in args

    def test_post_process_empty(self, module: SipStatsModule):
        """Test post-processing with empty input."""
        result = module.post_process("")
        assert "No SIP messages found" in result

    def test_post_process_with_data(self, module: SipStatsModule):
        """Test post-processing with sample SIP data."""
        # Sample tshark output: src_ip, tcp_src, udp_src, dst_ip, tcp_dst, udp_dst, method, status, status_line
        sample_output = (
            "10.0.0.1\t5060\t\t10.0.0.2\t5060\t\tINVITE\t\t\n"
            "10.0.0.2\t5060\t\t10.0.0.1\t5060\t\t\t200\tSIP/2.0 200 OK\n"
            "10.0.0.1\t5060\t\t10.0.0.2\t5060\t\tACK\t\t\n"
            "10.0.0.1\t5060\t\t10.0.0.2\t5060\t\tBYE\t\t\n"
            "10.0.0.2\t5060\t\t10.0.0.1\t5060\t\t\t200\tSIP/2.0 200 OK\n"
        )
        
        result = module.post_process(sample_output)
        
        # Check that output contains expected sections
        assert "SIP Statistics" in result
        assert "SIP Methods (Requests)" in result
        assert "SIP Response Codes" in result
        assert "Summary" in result
        
        # Check that methods are counted
        assert "INVITE" in result
        assert "ACK" in result
        assert "BYE" in result
        
        # Check that response codes are counted
        assert "200" in result
        
        # Check summary counts
        assert "Total SIP Requests:  3" in result
        assert "Total SIP Responses: 2" in result


class TestRtpStatsModule:
    """Tests for RTP statistics module."""

    @pytest.fixture
    def module(self) -> RtpStatsModule:
        """Create an RtpStatsModule instance."""
        return RtpStatsModule()

    def test_module_name(self, module: RtpStatsModule):
        """Test that module has correct name."""
        assert module.name == "rtp_stats"

    def test_output_suffix(self, module: RtpStatsModule):
        """Test that module has correct output suffix."""
        assert module.output_suffix == "rtp-stats.txt"

    def test_required_protocols(self, module: RtpStatsModule):
        """Test that module requires RTP protocol."""
        assert module.required_protocols == {"rtp"}

    def test_should_execute_with_rtp(self, module: RtpStatsModule):
        """Test that module executes when RTP is detected."""
        assert module.should_execute({"rtp"}) is True
        assert module.should_execute({"rtp", "sip"}) is True

    def test_should_not_execute_without_rtp(self, module: RtpStatsModule):
        """Test that module does not execute without RTP."""
        assert module.should_execute({"http"}) is False
        assert module.should_execute(set()) is False

    def test_build_tshark_args(self, module: RtpStatsModule):
        """Test tshark arguments generation."""
        args = module.build_tshark_args(Path("test.pcap"))
        assert isinstance(args, list)
        assert "-q" in args
        assert "-z" in args
        assert "rtp,streams" in args

    def test_post_process_empty(self, module: RtpStatsModule):
        """Test post-processing with empty input."""
        result = module.post_process("")
        assert "No RTP streams found" in result

    def test_post_process_with_data(self, module: RtpStatsModule):
        """Test post-processing with sample RTP stream data."""
        # Sample tshark rtp,streams output
        sample_output = """========================= RTP Streams ========================
   Start time      End time     Src IP addr  Port    Dest IP addr  Port       SSRC          Payload  Pkts         Lost   Min Delta(ms)  Mean Delta(ms)   Max Delta(ms)  Min Jitter(ms) Mean Jitter(ms)  Max Jitter(ms) Problems?
    21.926954     77.421975    10.135.65.10 16676   10.128.131.17 19490 0x000079BE            g711U  2776     0 (0.0%)          18.996          19.998          21.047           0.002           0.021           0.389 
=============================================================="""
        
        result = module.post_process(sample_output)
        
        # Check that output contains expected sections
        assert "RTP Stream Statistics" in result
        assert "Stream Details" in result
        assert "Quality Analysis" in result
        assert "Summary" in result
        
        # Check quality assessment
        assert "Quality: Good" in result or "Quality: ✓ GOOD" in result


class TestSshStatsModule:
    """Tests for SSH statistics module."""

    @pytest.fixture
    def module(self) -> SshStatsModule:
        """Create an SshStatsModule instance."""
        return SshStatsModule()

    def test_module_name(self, module: SshStatsModule):
        """Test that module has correct name."""
        assert module.name == "ssh_stats"

    def test_output_suffix(self, module: SshStatsModule):
        """Test that module has correct output suffix."""
        assert module.output_suffix == "ssh-stats.txt"

    def test_required_protocols(self, module: SshStatsModule):
        """Test that module requires SSH protocol."""
        assert module.required_protocols == {"ssh"}

    def test_should_execute_with_ssh(self, module: SshStatsModule):
        """Test that module executes when SSH is detected."""
        assert module.should_execute({"ssh"}) is True
        assert module.should_execute({"ssh", "tcp"}) is True

    def test_should_not_execute_without_ssh(self, module: SshStatsModule):
        """Test that module does not execute without SSH."""
        assert module.should_execute({"http"}) is False
        assert module.should_execute(set()) is False

    def test_build_tshark_args(self, module: SshStatsModule):
        """Test tshark arguments generation."""
        args = module.build_tshark_args(Path("test.pcap"))
        assert isinstance(args, list)
        assert "-Y" in args
        assert "ssh" in args
        assert "-T" in args
        assert "fields" in args
        assert "-e" in args
        assert "tcp.stream" in args
        assert "ssh.protocol" in args

    def test_post_process_empty(self, module: SshStatsModule):
        """Test post-processing with empty input."""
        result = module.post_process("")
        assert "No SSH traffic found" in result

    def test_post_process_with_data(self, module: SshStatsModule):
        """Test post-processing with sample SSH data."""
        # Sample tshark output: frame, src_ip, src_port, dst_ip, dst_port, stream, protocol
        sample_output = (
            "1\t10.0.0.1\t22\t10.0.0.2\t54321\t0\tSSH-2.0-OpenSSH_8.0\n"
            "2\t10.0.0.2\t54321\t10.0.0.1\t22\t0\tSSH-2.0-OpenSSH_7.9\n"
            "3\t10.0.0.1\t22\t10.0.0.2\t54321\t0\t\n"
            "4\t10.0.0.2\t54321\t10.0.0.1\t22\t0\t\n"
        )
        
        result = module.post_process(sample_output)
        
        # Check that output contains expected sections
        assert "SSH Statistics" in result
        assert "SSH Connections" in result
        assert "Summary" in result
        
        # Check stream information
        assert "Stream 0" in result or "Stream     0" in result
        
        # Check summary counts
        assert "Total SSH Streams:" in result
        assert "Total SSH Packets:" in result


class TestVoIPModulesIntegration:
    """Integration tests for VoIP modules with real PCAP file."""

    @pytest.fixture
    def voip_pcap(self) -> Path:
        """Return path to VOIP test PCAP file."""
        pcap_path = Path("cases_02/V-001/VOIP.pcap")
        if not pcap_path.exists():
            # Try alternative path
            pcap_path = Path("cases/V-001/VOIP.pcap")
        if not pcap_path.exists():
            pytest.skip(f"VOIP test PCAP file not found")
        return pcap_path

    def test_sip_module_with_real_pcap(self, voip_pcap: Path):
        """Test SIP module with real VOIP.pcap file."""
        from capmaster.core.tshark_wrapper import TsharkWrapper
        
        module = SipStatsModule()
        tshark = TsharkWrapper()
        
        # Execute tshark
        args = module.build_tshark_args(voip_pcap)
        result = tshark.execute(args=args, input_file=voip_pcap)
        
        # Post-process
        output = module.post_process(result.stdout)
        
        # Verify output
        assert "SIP Statistics" in output
        assert "OPTIONS" in output or "INVITE" in output or "Total SIP" in output

    def test_rtp_module_with_real_pcap(self, voip_pcap: Path):
        """Test RTP module with real VOIP.pcap file."""
        from capmaster.core.tshark_wrapper import TsharkWrapper
        
        module = RtpStatsModule()
        tshark = TsharkWrapper()
        
        # Execute tshark
        args = module.build_tshark_args(voip_pcap)
        result = tshark.execute(args=args, input_file=voip_pcap)
        
        # Post-process
        output = module.post_process(result.stdout)
        
        # Verify output
        assert "RTP Stream Statistics" in output or "RTP Streams" in output

    def test_ssh_module_with_real_pcap(self, voip_pcap: Path):
        """Test SSH module with real VOIP.pcap file."""
        from capmaster.core.tshark_wrapper import TsharkWrapper
        
        module = SshStatsModule()
        tshark = TsharkWrapper()
        
        # Execute tshark
        args = module.build_tshark_args(voip_pcap)
        result = tshark.execute(args=args, input_file=voip_pcap)
        
        # Post-process
        output = module.post_process(result.stdout)
        
        # Verify output
        assert "SSH Statistics" in output or "No SSH traffic found" in output

