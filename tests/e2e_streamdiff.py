import subprocess
import sys
from pathlib import Path
import shutil

# Configuration
CAPMASTER_BIN = [sys.executable, "-m", "capmaster"]
TEST_DATA_DIR = Path("cases_02")
DUAL_PCAP_DIR = TEST_DATA_DIR / "TC-001-1-20160407"
PCAP_A = DUAL_PCAP_DIR / "TC-001-1-20160407-A.pcap"
PCAP_B = DUAL_PCAP_DIR / "TC-001-1-20160407-B.pcap"
OUTPUT_DIR = Path("tests/e2e_output_streamdiff")

def run_command(args, description, expect_success=True, expect_output=True):
    print(f"Running: {description}")
    print(f"Command: {' '.join(str(a) for a in args)}")
    
    result = subprocess.run(
        args,
        capture_output=True,
        text=True
    )
    
    if expect_success and result.returncode != 0:
        print(f"❌ FAILED: Expected success, got exit code {result.returncode}")
        print("Stderr:", result.stderr)
        return False
    
    if not expect_success and result.returncode == 0:
        print(f"❌ FAILED: Expected failure, got exit code 0")
        return False
        
    if not expect_output and (len(result.stdout.strip()) > 0 or len(result.stderr.strip()) > 0):
        print(f"⚠️  WARNING: Expected no output, got {len(result.stdout)} bytes stdout, {len(result.stderr)} bytes stderr")

    print("✅ PASSED")
    return True

def main():
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True)

    success = True

    # 5. StreamDiff Plugin
    print("\n--- Testing StreamDiff Plugin ---")
    # Normal (using explicit stream IDs to avoid needing matched-connections file)
    success &= run_command(
        CAPMASTER_BIN + ["streamdiff", "--file1", str(PCAP_A), "--file2", str(PCAP_B), "--file1-stream-id", "0", "--file2-stream-id", "0", "-o", str(OUTPUT_DIR / "streamdiff_normal.txt")],
        "StreamDiff Normal"
    )
    # Quiet
    success &= run_command(
        CAPMASTER_BIN + ["streamdiff", "--file1", str(PCAP_A), "--file2", str(PCAP_B), "--file1-stream-id", "0", "--file2-stream-id", "0", "-o", str(OUTPUT_DIR / "streamdiff_quiet.txt"), "-q"],
        "StreamDiff Quiet",
        expect_output=False
    )
    # Allow No Input (1 file)
    success &= run_command(
        CAPMASTER_BIN + ["streamdiff", "--file1", str(PCAP_A), "--allow-no-input"],
        "StreamDiff Allow No Input",
        expect_success=True
    )

    if success:
        print("\n🎉 All StreamDiff Tests Passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
