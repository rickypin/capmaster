"""Tests for VoIP quality assessment module."""

import pytest
from pathlib import Path

from capmaster.plugins.analyze.modules import get_all_modules, discover_modules
from capmaster.plugins.analyze.modules.voip_quality import VoipQualityModule


# Discover all modules before running tests
discover_modules()


class TestVoipQualityModule:
    """Tests for VoIP quality assessment module."""

    def test_module_registered(self):
        """Test that VoIP quality module is registered."""
        modules = get_all_modules()
        assert VoipQualityModule in modules

    def test_module_name(self):
        """Test module name."""
        module = VoipQualityModule()
        assert module.name == "voip_quality"

    def test_output_suffix(self):
        """Test output file suffix."""
        module = VoipQualityModule()
        assert module.output_suffix == "voip-quality.txt"

    def test_required_protocols(self):
        """Test required protocols."""
        module = VoipQualityModule()
        assert module.required_protocols == {"rtp"}

    def test_build_tshark_args(self):
        """Test tshark arguments generation."""
        module = VoipQualityModule()
        args = module.build_tshark_args(Path("test.pcap"))
        
        assert "-q" in args
        assert "-z" in args
        assert "rtp,streams" in args

    def test_post_process_empty(self):
        """Test post-processing with empty input."""
        module = VoipQualityModule()
        result = module.post_process("")
        assert "No RTP streams found" in result

    def test_calculate_mos_excellent(self):
        """Test MOS calculation for excellent quality."""
        module = VoipQualityModule()
        
        # No packet loss, low jitter
        mos, rating = module._calculate_mos(0.0, 5.0, "g711U")
        
        assert mos >= 4.0
        assert rating in ["Excellent", "Good"]

    def test_calculate_mos_poor(self):
        """Test MOS calculation for poor quality."""
        module = VoipQualityModule()
        
        # High packet loss, high jitter
        mos, rating = module._calculate_mos(10.0, 100.0, "g711U")
        
        assert mos < 3.5
        assert rating in ["Poor", "Bad"]

    def test_calculate_mos_different_codecs(self):
        """Test MOS calculation with different codecs."""
        module = VoipQualityModule()
        
        # G.711 should have higher base quality than G.729
        mos_g711, _ = module._calculate_mos(0.0, 10.0, "g711U")
        mos_g729, _ = module._calculate_mos(0.0, 10.0, "g729")
        
        assert mos_g711 > mos_g729

    def test_post_process_with_data(self):
        """Test post-processing with sample RTP stream data."""
        module = VoipQualityModule()
        
        # Sample tshark RTP streams output
        sample_output = """========================= RTP Streams ========================
   Start time      End time     Src IP addr  Port    Dest IP addr  Port       SSRC          Payload  Pkts         Lost   Min Delta(ms)  Mean Delta(ms)   Max Delta(ms)  Min Jitter(ms) Mean Jitter(ms)  Max Jitter(ms) Problems?
    21.926954     77.421975    10.135.65.10 16676   10.128.131.17 19490 0x000079BE            g711U  2776     0 (0.0%)          18.996          19.998          21.047           0.002           0.021           0.389 
=============================================================="""
        
        result = module.post_process(sample_output)
        
        # Check summary
        assert "VoIP Quality Assessment" in result
        assert "Total RTP Streams:" in result
        assert "1" in result
        
        # Check MOS score
        assert "MOS Score:" in result
        assert "Average MOS Score:" in result
        
        # Check quality rating
        assert "Quality Distribution:" in result
        
        # Check stream details
        assert "Stream Details:" in result
        assert "10.135.65.10:16676" in result
        assert "10.128.131.17:19490" in result
        assert "g711U" in result

    def test_post_process_multiple_streams(self):
        """Test post-processing with multiple RTP streams."""
        module = VoipQualityModule()
        
        # Sample with multiple streams
        sample_output = """========================= RTP Streams ========================
   Start time      End time     Src IP addr  Port    Dest IP addr  Port       SSRC          Payload  Pkts         Lost   Min Delta(ms)  Mean Delta(ms)   Max Delta(ms)  Min Jitter(ms) Mean Jitter(ms)  Max Jitter(ms) Problems?
    21.926954     77.421975    10.135.65.10 16676   10.128.131.17 19490 0x000079BE            g711U  2776     0 (0.0%)          18.996          19.998          21.047           0.002           0.021           0.389 
    22.000000     78.000000    10.135.65.11 16677   10.128.131.18 19491 0x000079BF            g729   2500   125 (5.0%)          18.500          20.000          22.000           0.010           0.050           0.500 
=============================================================="""
        
        result = module.post_process(sample_output)
        
        # Check that both streams are processed
        assert "Total RTP Streams:       2" in result
        assert "Stream 1:" in result
        assert "Stream 2:" in result
        
        # Check average MOS
        assert "Average MOS Score:" in result

    def test_post_process_with_quality_issues(self):
        """Test post-processing with quality issues."""
        module = VoipQualityModule()
        
        # Sample with high packet loss and jitter
        sample_output = """========================= RTP Streams ========================
   Start time      End time     Src IP addr  Port    Dest IP addr  Port       SSRC          Payload  Pkts         Lost   Min Delta(ms)  Mean Delta(ms)   Max Delta(ms)  Min Jitter(ms) Mean Jitter(ms)  Max Jitter(ms) Problems?
    21.926954     77.421975    10.135.65.10 16676   10.128.131.17 19490 0x000079BE            g711U  2000   120 (6.0%)          18.996          19.998          21.047           0.002          35.000          80.000 
=============================================================="""
        
        result = module.post_process(sample_output)
        
        # Check that issues are detected
        assert "Issues:" in result
        assert ("HIGH packet loss" in result or "packet loss" in result)
        assert ("HIGH jitter" in result or "jitter" in result)

    def test_mos_range_validation(self):
        """Test that MOS scores are within valid range."""
        module = VoipQualityModule()
        
        # Test extreme values
        test_cases = [
            (0.0, 0.0, "g711U"),      # Perfect conditions
            (100.0, 1000.0, "g711U"), # Worst conditions
            (50.0, 500.0, "g729"),    # Very poor conditions
        ]
        
        for loss, jitter, codec in test_cases:
            mos, rating = module._calculate_mos(loss, jitter, codec)
            
            # MOS should be between 1.0 and 5.0
            assert 1.0 <= mos <= 5.0
            
            # Rating should be valid
            assert rating in ["Excellent", "Good", "Fair", "Poor", "Bad"]

    def test_recommendations_generation(self):
        """Test that recommendations are generated based on quality."""
        module = VoipQualityModule()
        
        # Good quality stream
        good_output = """========================= RTP Streams ========================
   Start time      End time     Src IP addr  Port    Dest IP addr  Port       SSRC          Payload  Pkts         Lost   Min Delta(ms)  Mean Delta(ms)   Max Delta(ms)  Min Jitter(ms) Mean Jitter(ms)  Max Jitter(ms) Problems?
    21.926954     77.421975    10.135.65.10 16676   10.128.131.17 19490 0x000079BE            g711U  2776     0 (0.0%)          18.996          19.998          21.047           0.002           0.021           0.389 
=============================================================="""
        
        result = module.post_process(good_output)
        
        # Should have recommendations section
        assert "Recommendations:" in result
        
        # For good quality, should recommend no action
        assert ("No immediate action required" in result or "good" in result.lower())

