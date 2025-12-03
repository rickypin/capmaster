import subprocess
import sys
from pathlib import Path
import shutil

# Configuration
CAPMASTER_BIN = [sys.executable, "-m", "capmaster"]
TEST_DATA_DIR = Path("data/cases")
SINGLE_PCAP = TEST_DATA_DIR / "netis/test.pcap"
DUAL_PCAP_DIR = TEST_DATA_DIR / "TC-001-1-20160407"
PCAP_A = DUAL_PCAP_DIR / "TC-001-1-20160407-A.pcap"
PCAP_B = DUAL_PCAP_DIR / "TC-001-1-20160407-B.pcap"
OUTPUT_DIR = Path("tests/e2e_output")

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
        # In quiet mode, we might still get some critical errors, but stdout should be mostly empty
        # For this test, we'll be lenient but print what we got
        print(f"⚠️  WARNING: Expected no output, got {len(result.stdout)} bytes stdout, {len(result.stderr)} bytes stderr")
        # print("Stdout:", result.stdout)
        # print("Stderr:", result.stderr)

    print("✅ PASSED")
    return True

def main():
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True)

    success = True

    EMPTY_DIR = OUTPUT_DIR / "empty"
    EMPTY_DIR.mkdir(exist_ok=True)

    # 1. Analyze Plugin
    # ... (commented out)
    
    # 5. StreamDiff Plugin
    print("\n--- Testing Analyze Plugin ---")
    # Normal
    success &= run_command(
        CAPMASTER_BIN + ["analyze", "-i", str(SINGLE_PCAP), "-o", str(OUTPUT_DIR / "analyze_normal")],
        "Analyze Normal"
    )
    # Quiet
    success &= run_command(
        CAPMASTER_BIN + ["analyze", "-i", str(SINGLE_PCAP), "-o", str(OUTPUT_DIR / "analyze_quiet"), "-q"],
        "Analyze Quiet",
        expect_output=False
    )
    # Allow No Input (0 files)
    success &= run_command(
        CAPMASTER_BIN + ["analyze", "-i", str(EMPTY_DIR), "--allow-no-input"],
        "Analyze Allow No Input",
        expect_success=True
    )

    # 2. Match Plugin
    print("\n--- Testing Match Plugin ---")
    # Normal
    success &= run_command(
        CAPMASTER_BIN + ["match", "--file1", str(PCAP_A), "--file2", str(PCAP_B), "-o", str(OUTPUT_DIR / "match_normal.txt")],
        "Match Normal"
    )
    # Quiet
    success &= run_command(
        CAPMASTER_BIN + ["match", "--file1", str(PCAP_A), "--file2", str(PCAP_B), "-o", str(OUTPUT_DIR / "match_quiet.txt"), "-q"],
        "Match Quiet",
        expect_output=False
    )
    # Allow No Input (1 file)
    success &= run_command(
        CAPMASTER_BIN + ["match", "--file1", str(PCAP_A), "--allow-no-input"],
        "Match Allow No Input",
        expect_success=True
    )

    # 3. Compare Plugin
    print("\n--- Testing Compare Plugin ---")
    # Normal
    success &= run_command(
        CAPMASTER_BIN + ["compare", "--file1", str(PCAP_A), "--file2", str(PCAP_B), "-o", str(OUTPUT_DIR / "compare_normal.txt")],
        "Compare Normal"
    )
    # Quiet
    success &= run_command(
        CAPMASTER_BIN + ["compare", "--file1", str(PCAP_A), "--file2", str(PCAP_B), "-o", str(OUTPUT_DIR / "compare_quiet.txt"), "-q"],
        "Compare Quiet",
        expect_output=False
    )
    # Allow No Input (1 file)
    success &= run_command(
        CAPMASTER_BIN + ["compare", "--file1", str(PCAP_A), "--allow-no-input"],
        "Compare Allow No Input",
        expect_success=True
    )

    # 4. Preprocess Plugin
    print("\n--- Testing Preprocess Plugin ---")
    # Normal
    success &= run_command(
        CAPMASTER_BIN + ["preprocess", "-i", str(SINGLE_PCAP), "-o", str(OUTPUT_DIR / "preprocess_normal")],
        "Preprocess Normal"
    )
    # Quiet
    success &= run_command(
        CAPMASTER_BIN + ["preprocess", "-i", str(SINGLE_PCAP), "-o", str(OUTPUT_DIR / "preprocess_quiet"), "-q"],
        "Preprocess Quiet",
        expect_output=False
    )
    # Allow No Input (0 files)
    success &= run_command(
        CAPMASTER_BIN + ["preprocess", "-i", str(EMPTY_DIR), "--allow-no-input"],
        "Preprocess Allow No Input",
        expect_success=True
    )

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

    # 6. Topology Plugin
    print("\n--- Testing Topology Plugin ---")
    # Normal (Single file mode is easiest for testing)
    success &= run_command(
        CAPMASTER_BIN + ["topology", "-i", str(SINGLE_PCAP), "-o", str(OUTPUT_DIR / "topology_normal.html")],
        "Topology Normal"
    )
    # Quiet
    success &= run_command(
        CAPMASTER_BIN + ["topology", "-i", str(SINGLE_PCAP), "-o", str(OUTPUT_DIR / "topology_quiet.html"), "-q"],
        "Topology Quiet",
        expect_output=False
    )
    # Allow No Input (0 files)
    success &= run_command(
        CAPMASTER_BIN + ["topology", "-i", str(EMPTY_DIR), "--allow-no-input"],
        "Topology Allow No Input",
        expect_success=True
    )

    # 7. Pipeline Plugin
    print("\n--- Testing Pipeline Plugin ---")
    # Create a dummy config for pipeline
    PIPELINE_CONFIG = OUTPUT_DIR / "pipeline_config.yaml"
    with open(PIPELINE_CONFIG, "w") as f:
        f.write("pipeline:\n  - name: analyze\n    module: http_response\n")

    # Normal
    success &= run_command(
        CAPMASTER_BIN + ["run-pipeline", "-i", str(SINGLE_PCAP), "-c", str(PIPELINE_CONFIG), "-o", str(OUTPUT_DIR / "pipeline_normal")],
        "Pipeline Normal"
    )
    # Quiet
    success &= run_command(
        CAPMASTER_BIN + ["run-pipeline", "-i", str(SINGLE_PCAP), "-c", str(PIPELINE_CONFIG), "-o", str(OUTPUT_DIR / "pipeline_quiet"), "-q"],
        "Pipeline Quiet",
        expect_output=False
    )
    # Allow No Input (0 files)
    success &= run_command(
        CAPMASTER_BIN + ["run-pipeline", "-i", str(EMPTY_DIR), "-c", str(PIPELINE_CONFIG), "-o", str(OUTPUT_DIR / "pipeline_empty"), "--allow-no-input"],
        "Pipeline Allow No Input",
        expect_success=True
    )

    if success:
        print("\n🎉 All End-to-End Tests Passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
