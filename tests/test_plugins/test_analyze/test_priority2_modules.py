"""Tests for priority 2 analysis modules (JSON, XML, FTP-DATA, MQ)."""

import pytest
from pathlib import Path

from capmaster.plugins.analyze.modules import get_all_modules, discover_modules
from capmaster.plugins.analyze.modules.json_stats import JsonStatsModule
from capmaster.plugins.analyze.modules.xml_stats import XmlStatsModule
from capmaster.plugins.analyze.modules.ftp_data_stats import FtpDataStatsModule
from capmaster.plugins.analyze.modules.mq_stats import MqStatsModule


# Discover all modules before running tests
discover_modules()


class TestJsonStatsModule:
    """Tests for JSON statistics module."""

    def test_module_registered(self):
        """Test that JSON stats module is registered."""
        modules = get_all_modules()
        assert JsonStatsModule in modules

    def test_module_name(self):
        """Test module name."""
        module = JsonStatsModule()
        assert module.name == "json_stats"

    def test_output_suffix(self):
        """Test output file suffix."""
        module = JsonStatsModule()
        assert module.output_suffix == "json-stats.txt"

    def test_required_protocols(self):
        """Test required protocols."""
        module = JsonStatsModule()
        assert module.required_protocols == {"json"}

    def test_build_tshark_args(self):
        """Test tshark arguments generation."""
        module = JsonStatsModule()
        args = module.build_tshark_args(Path("test.pcap"))
        
        assert "-Y" in args
        assert "json" in args
        assert "-T" in args
        assert "fields" in args
        assert "-e" in args
        assert "http.request.method" in args
        assert "http.response.code" in args

    def test_post_process_empty(self):
        """Test post-processing with empty input."""
        module = JsonStatsModule()
        result = module.post_process("")
        assert "No JSON messages found" in result

    def test_post_process_with_data(self):
        """Test post-processing with sample data."""
        module = JsonStatsModule()

        # Sample tshark output (tab-separated)
        # Fields: frame.number, frame.len, ip.src, tcp.srcport, ip.dst, tcp.dstport,
        #         http.request.method, http.response.code, http.content_type, http.content_length
        sample_output = (
            "4\t1796\t173.173.0.44\t58061\t2.20.102.63\t80\tPOST\t\tapplication/json\t500\n"
            "5\t1200\t2.20.102.63\t80\t173.173.0.44\t58061\t\t200\tapplication/json\t300\n"
            "16\t800\t173.173.0.44\t49349\t2.20.102.63\t80\tGET\t\tapplication/json\t200\n"
        )

        result = module.post_process(sample_output)

        # Check summary
        assert "Total JSON Messages:" in result
        assert "3" in result

        # Check methods
        assert "HTTP Methods" in result
        assert "POST" in result
        assert "GET" in result

        # Check response codes
        assert "HTTP Response Codes" in result
        assert "200" in result
        assert "Success" in result


class TestXmlStatsModule:
    """Tests for XML statistics module."""

    def test_module_registered(self):
        """Test that XML stats module is registered."""
        modules = get_all_modules()
        assert XmlStatsModule in modules

    def test_module_name(self):
        """Test module name."""
        module = XmlStatsModule()
        assert module.name == "xml_stats"

    def test_output_suffix(self):
        """Test output file suffix."""
        module = XmlStatsModule()
        assert module.output_suffix == "xml-stats.txt"

    def test_required_protocols(self):
        """Test required protocols."""
        module = XmlStatsModule()
        assert module.required_protocols == {"xml"}

    def test_build_tshark_args(self):
        """Test tshark arguments generation."""
        module = XmlStatsModule()
        args = module.build_tshark_args(Path("test.pcap"))
        
        assert "-Y" in args
        assert "xml" in args
        assert "-T" in args
        assert "fields" in args
        assert "http.request.method" in args
        assert "http.response.code" in args

    def test_post_process_empty(self):
        """Test post-processing with empty input."""
        module = XmlStatsModule()
        result = module.post_process("")
        assert "No XML messages found" in result

    def test_post_process_with_data(self):
        """Test post-processing with sample data."""
        module = XmlStatsModule()
        
        # Sample tshark output
        sample_output = (
            "5\t748\t10.112.195.130\t80\t10.116.193.91\t46590\tPOST\t\ttext/xml\t500\n"
            "10\t800\t10.116.193.91\t46590\t10.112.195.130\t80\t\t200\ttext/xml\t600\n"
            "13\t900\t10.112.195.130\t80\t10.116.193.93\t36858\tPOST\t\tapplication/soap+xml\t700\n"
        )
        
        result = module.post_process(sample_output)
        
        # Check summary
        assert "Total XML Messages:" in result
        assert "3" in result
        
        # Check SOAP detection
        assert "SOAP Messages:" in result
        assert "1" in result
        
        # Check content types
        assert "Content Types:" in result
        assert "text/xml" in result
        assert "SOAP" in result or "XML" in result


class TestFtpDataStatsModule:
    """Tests for FTP-DATA statistics module."""

    def test_module_registered(self):
        """Test that FTP-DATA stats module is registered."""
        modules = get_all_modules()
        assert FtpDataStatsModule in modules

    def test_module_name(self):
        """Test module name."""
        module = FtpDataStatsModule()
        assert module.name == "ftp_data_stats"

    def test_output_suffix(self):
        """Test output file suffix."""
        module = FtpDataStatsModule()
        assert module.output_suffix == "ftp-data-stats.txt"

    def test_required_protocols(self):
        """Test required protocols."""
        module = FtpDataStatsModule()
        assert module.required_protocols == {"ftp-data"}

    def test_build_tshark_args(self):
        """Test tshark arguments generation."""
        module = FtpDataStatsModule()
        args = module.build_tshark_args(Path("test.pcap"))
        
        assert "-Y" in args
        assert "ftp-data" in args
        assert "-T" in args
        assert "fields" in args
        assert "tcp.stream" in args
        assert "tcp.len" in args

    def test_post_process_empty(self):
        """Test post-processing with empty input."""
        module = FtpDataStatsModule()
        result = module.post_process("")
        assert "No FTP-DATA transfers found" in result

    def test_post_process_with_data(self):
        """Test post-processing with sample data."""
        module = FtpDataStatsModule()
        
        # Sample tshark output
        sample_output = (
            "25\t0.001\t10.200.33.34\t20\t10.200.16.30\t50841\t1\t1460\t1518\n"
            "26\t0.002\t10.200.33.34\t20\t10.200.16.30\t50841\t1\t1460\t1518\n"
            "58\t0.010\t10.200.33.34\t20\t10.200.16.30\t50845\t2\t81\t139\n"
        )
        
        result = module.post_process(sample_output)

        # Check summary
        assert "FTP-DATA Transfer Statistics" in result
        assert "Summary:" in result
        assert "Total FTP-DATA Streams:" in result

        # Check highlighted transfers
        assert "Highlighted Transfers:" in result
        assert "Stream,Packets,Payload" in result
        assert "Severity" in result

        # Check size distribution section
        assert "Transfer Size Distribution:" in result
        assert "Size Range" in result


class TestMqStatsModule:
    """Tests for MQ statistics module."""

    def test_module_registered(self):
        """Test that MQ stats module is registered."""
        modules = get_all_modules()
        assert MqStatsModule in modules

    def test_module_name(self):
        """Test module name."""
        module = MqStatsModule()
        assert module.name == "mq_stats"

    def test_output_suffix(self):
        """Test output file suffix."""
        module = MqStatsModule()
        assert module.output_suffix == "mq-stats.txt"

    def test_required_protocols(self):
        """Test required protocols."""
        module = MqStatsModule()
        assert module.required_protocols == {"mq"}

    def test_build_tshark_args(self):
        """Test tshark arguments generation."""
        module = MqStatsModule()
        args = module.build_tshark_args(Path("test.pcap"))

        assert "-Y" in args
        assert "mq" in args
        assert "-T" in args
        assert "fields" in args
        assert "tcp.stream" in args
        # Verify new fields for completion and reason codes
        assert "mq.api.completioncode" in args
        assert "mq.api.reasoncode" in args

    def test_post_process_empty(self):
        """Test post-processing with empty input."""
        module = MqStatsModule()
        result = module.post_process("")
        assert "No MQ messages found" in result

    def test_post_process_with_data(self):
        """Test post-processing with sample data (old format without codes)."""
        module = MqStatsModule()

        # Sample tshark output (old format - 7 fields)
        sample_output = (
            "166246\t1522\t16.1.2.29\t54888\t16.1.2.48\t9248\t13437\n"
        )

        result = module.post_process(sample_output)

        # Check summary
        assert "Total MQ Messages:" in result
        assert "1" in result

        # Check streams
        assert "MQ Streams" in result
        assert "13437" in result

    def test_post_process_with_completion_codes(self):
        """Test post-processing with completion and reason codes."""
        module = MqStatsModule()

        # Sample tshark output with completion and reason codes
        # Format: frame, len, src_ip, src_port, dst_ip, dst_port, stream, completion_code, reason_code
        sample_output = (
            "100\t1522\t16.1.2.29\t54888\t16.1.2.48\t9248\t13437\t0\t0\n"      # Success
            "101\t1522\t16.1.2.29\t54888\t16.1.2.48\t9248\t13437\t2\t2009\n"   # Failed
            "102\t1522\t16.1.2.29\t54888\t16.1.2.48\t9248\t13437\t1\t2024\n"   # Warning
        )

        result = module.post_process(sample_output)

        # Check summary
        assert "Total MQ Messages:" in result
        assert "3" in result

        # Check error detection
        assert "Error Messages:" in result
        assert "2" in result  # 2 non-zero completion codes

        # Check completion code statistics
        assert "Completion Code Statistics:" in result
        assert "0" in result  # Success code
        assert "2" in result  # Failed code
        assert "1" in result  # Warning code

        # Check reason code statistics
        assert "Reason Code Statistics" in result
        assert "2009" in result
        assert "2024" in result

