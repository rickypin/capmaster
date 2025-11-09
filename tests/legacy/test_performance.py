"""
Performance tests for capmaster.

Ensures that the new Python implementation performs at least 90% as fast
as the original shell scripts.
"""

import subprocess
import tempfile
import time
from pathlib import Path

import pytest


class TestAnalyzePerformance:
    """Performance tests for analyze plugin."""

    @pytest.fixture
    def test_file(self):
        """Test PCAP file."""
        return "cases/V-001/VOIP.pcap"

    def measure_original_script(self, test_file: str, iterations: int = 3) -> float:
        """Measure execution time of original script."""
        times = []
        
        for _ in range(iterations):
            with tempfile.TemporaryDirectory() as output_dir:
                script = Path.cwd() / "analyze_pcap.sh"
                cmd = [str(script), "-i", test_file, "-o", output_dir]
                
                start = time.time()
                result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(Path.cwd()))
                end = time.time()
                
                assert result.returncode == 0, f"Original script failed: {result.stderr}"
                times.append(end - start)
        
        # Return average time
        return sum(times) / len(times)

    def measure_new_implementation(self, test_file: str, iterations: int = 3) -> float:
        """Measure execution time of new implementation."""
        times = []
        
        for _ in range(iterations):
            with tempfile.TemporaryDirectory() as output_dir:
                cmd = ["python", "-m", "capmaster", "analyze", "-i", test_file, "-o", output_dir]
                
                start = time.time()
                result = subprocess.run(cmd, capture_output=True, text=True)
                end = time.time()
                
                assert result.returncode == 0, f"New implementation failed: {result.stderr}"
                times.append(end - start)
        
        # Return average time
        return sum(times) / len(times)

    def test_analyze_performance(self, test_file):
        """Test that analyze performance is >= 90% of original script."""
        print(f"\nPerformance test for: {test_file}")
        
        # Measure original script
        original_time = self.measure_original_script(test_file)
        print(f"Original script average time: {original_time:.3f}s")
        
        # Measure new implementation
        new_time = self.measure_new_implementation(test_file)
        print(f"New implementation average time: {new_time:.3f}s")
        
        # Calculate performance ratio
        performance_ratio = original_time / new_time if new_time > 0 else 0
        print(f"Performance ratio: {performance_ratio:.2%}")
        
        # Assert that new implementation is at least 90% as fast
        # (i.e., takes at most 111% of the time)
        max_allowed_time = original_time * 1.11
        print(f"Max allowed time (110% of original): {max_allowed_time:.3f}s")
        
        assert new_time <= max_allowed_time, (
            f"Performance degradation detected: "
            f"new implementation took {new_time:.3f}s, "
            f"but should be <= {max_allowed_time:.3f}s "
            f"(original: {original_time:.3f}s)"
        )
        
        print(f"✓ Performance test passed!")

    def test_analyze_performance_detailed(self, test_file):
        """Detailed performance breakdown."""
        print(f"\nDetailed performance test for: {test_file}")
        
        # Run multiple iterations for more accurate measurement
        iterations = 5
        
        original_time = self.measure_original_script(test_file, iterations)
        new_time = self.measure_new_implementation(test_file, iterations)
        
        print(f"\nResults (average of {iterations} runs):")
        print(f"  Original script:      {original_time:.3f}s")
        print(f"  New implementation:   {new_time:.3f}s")
        print(f"  Difference:           {new_time - original_time:+.3f}s")
        print(f"  Performance ratio:    {(original_time / new_time * 100):.1f}%")
        
        if new_time < original_time:
            print(f"  ✓ New implementation is FASTER by {((original_time - new_time) / original_time * 100):.1f}%")
        else:
            print(f"  ⚠ New implementation is slower by {((new_time - original_time) / original_time * 100):.1f}%")


if __name__ == "__main__":
    # Run performance tests
    test = TestAnalyzePerformance()
    test_file = "cases/V-001/VOIP.pcap"
    
    print("=" * 70)
    print("CapMaster Performance Test")
    print("=" * 70)
    
    test.test_analyze_performance(test_file)
    test.test_analyze_performance_detailed(test_file)
    
    print("\n" + "=" * 70)
    print("Performance test completed!")
    print("=" * 70)

