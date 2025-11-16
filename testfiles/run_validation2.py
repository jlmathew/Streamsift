#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  @file      run_validation.py
#  @author    James Mathewson
#  @version   1.2.3 alpha (Added Merging Test)
#  @brief     Reads manifest, executes StreamSift, and performs validation.
# =============================================================================

import logging
import subprocess
import os
import glob as pyglob
import shutil
import time
import shlex
import json

# --- Configuration ---
BINARY_PATH = "./streamsift"
OUTPUT_DIR = "./test_data"
MANIFEST_FILE = os.path.join(OUTPUT_DIR, "tests_manifest.json")

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# --- Helper Function for Merging (Simulates C++ Post-Processing) ---
def is_merge_enabled(cli_args):
    """Checks if the merge flag is set to true in the CLI arguments."""
    try:
        m_index = cli_args.index("-m")
        return cli_args[m_index + 1].lower() == "true"
    except ValueError:
        try:
            m_index = cli_args.index("--merge-output")
            return cli_args[m_index + 1].lower() == "true"
        except ValueError:
            return False

def run_test(test):
    test_id = test['id']
    prefix = os.path.join(OUTPUT_DIR, f"out_{test_id}")
    pcap = test['pcap_file']
   
    # Clean previous output files for this run
    for f in pyglob.glob(f"{prefix}_*"): os.remove(f)
   
    results = {}
   
    # Run loop (j0 and j4 modes)
    for threads in test['test_modes']:
        mode_label = f"J{threads}"
       
        # Build command line arguments
        cmd = [BINARY_PATH, "-r", pcap, "-n", prefix]
        cmd.extend(["-j", str(threads)])
        cmd.extend(test['cli_args'])
       
        cmd_str = ' '.join(shlex.quote(arg) for arg in cmd)
        logger.info(f"[{mode_label}] CMD: {cmd_str}")

        try:
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
           
            # Allow time for file system flush, crucial for correctness
            time.sleep(0.5)
            actual_pcaps = len(pyglob.glob(f"{prefix}_*.pcap"))
            actual_detected = len(pyglob.glob(f"{prefix}_*.detected"))

            # --- Validation Checks ---
           
            expected_pcaps = test['expected_pcaps']
            passes_pcap_count = False
           
            # 1. Handle Merged Output Scenario
            if is_merge_enabled(test['cli_args']):
                # Expected: 1 master file and no individual streams left.
                # We check the actual file count against the expected count of master files (which is 1)
                passes_pcap_count = (actual_pcaps == 1)
                # We also check if the specific master file name exists (optional sanity check)
                # master_file_exists = os.path.exists(f"{prefix}_master.pcap")
                # passes_pcap_count = passes_pcap_count and master_file_exists # We don't use master.pcap name now, relies on C++ to clean up properly
            else:
                # 2. Standard individual file count
                passes_pcap_count = (actual_pcaps == expected_pcaps)
           
            # 3. Check special conditions (alerts, truncation)
            passes_alert_count = (actual_detected == test['expected_alerts'])
            passes_truncation = True
           
            if test['check_type'] == "TRUNCATION" and passes_pcap_count:
                 # Check file sizes are small (payload < 500 bytes)
                 for p in pyglob.glob(f"{prefix}_*.pcap"):
                     if os.path.getsize(p) > 200: # Simple heuristic check
                         passes_truncation = False
                         logger.warning(f"[{mode_label}] TRUNCATION FAILED: {p} is too large.")
                         break
           
            # 4. Final Result Synthesis
            passes_all = passes_pcap_count and passes_alert_count and passes_truncation
           
            result_status = "PASS" if passes_all else "FAIL"
           
            if result_status == "PASS":
                logger.info(f"[{mode_label}] RESULT: PASS (Saved: {actual_pcaps}, Alerts: {actual_detected})")
            else:
                logger.error(f"[{mode_label}] RESULT: FAIL (Expected Pcaps: {test['expected_pcaps']}, Got: {actual_pcaps}, Alerts: {actual_detected})")
           
            results[mode_label] = result_status
           
        except subprocess.TimeoutExpired:
            logger.error(f"[{mode_label}] TIMEOUT expired!")
            results[mode_label] = "TIMEOUT"
           
    return results

if __name__ == '__main__':
    if not os.path.exists(MANIFEST_FILE):
        logger.error(f"Manifest file not found at {MANIFEST_FILE}. Run generate_test_pcaps.py first!")
        exit(1)
       
    with open(MANIFEST_FILE, 'r') as f:
        manifest = json.load(f)
       
    full_report = {}
   
    print(f"\n--- Starting StreamSift Validation ({len(manifest)} Scenarios) ---")
   
    for test in manifest:
        full_report[test['id']] = run_test(test)
       
    print("\n\n=== FINAL TEST SUMMARY ===")
   
    total_tests = 0
    passed_tests = 0
   
    for test_id, results in full_report.items():
        for mode, status in results.items():
            total_tests += 1
            if status == "PASS":
                passed_tests += 1
            print(f"| {test_id:<15} | {mode:<5} | {status:<7} |")
   
    print(f"\nOverall Score: {passed_tests} / {total_tests} Tests Passed.")
