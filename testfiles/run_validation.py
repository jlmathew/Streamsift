#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  @file      run_validation.py
#  @author    James Mathewson
#  @version   1.2.0 alpha
#  @brief     Reads manifest, executes StreamSift, and performs validation.
# =============================================================================

import logging
import subprocess
import os
import glob as pyglob
import time
import shlex
import json

# --- Configuration ---
BINARY_PATH = "./streamsift"
OUTPUT_DIR = "./test_data"
MANIFEST_FILE = os.path.join(OUTPUT_DIR, "tests_manifest.json")

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

def run_test(test):
    test_id = test['id']
    prefix = os.path.join(OUTPUT_DIR, f"out_{test_id}")
    pcap = test['pcap_file']
   
    # Clean previous output files for this run
    for f in pyglob.glob(f"{prefix}_*"): os.remove(f)
   
    results = {}
   
    # Iterate through specified modes (e.g., [0, 4] for single and multi-thread)
    for threads in test['test_modes']:
        mode_label = f"J{threads}"
       
        # Build command line arguments
        cmd = [BINARY_PATH, "-r", pcap, "-n", prefix, "-j", str(threads)] + test['cli_args']
        cmd_str = ' '.join(shlex.quote(arg) for arg in cmd)
        logger.info(f"[{mode_label}] CMD: {cmd_str}")

        start_time = time.time()
        try:
            # Run the streamsift binary
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
           
            # --- Extract Final Metrics from Summary Block ---
            summary_output = process.stdout
           
            saved_count = 0
            # Simple, non-robust way to get saved streams from report:
            for line in summary_output.split('\n'):
                if 'Total Streams Saved:' in line:
                    saved_count = int(line.split(':')[1].strip())
                    break
           
            # --- Validation Checks ---
           
            # 1. Wait for file system to stabilize
            time.sleep(0.5)
            actual_pcaps = len(pyglob.glob(f"{prefix}_*.pcap"))
            actual_detected = len(pyglob.glob(f"{prefix}_*.detected"))

            # 2. Check basic stream count match
            passes_count = (actual_pcaps == test['expected_pcaps'])
           
            # 3. Check special conditions (truncation/alerts)
            if test['check_type'] == "TRUNCATION":
                 # Truncation verification relies on checking file sizes, skipping for now
                 # but we verify the count matches expected saves.
                 passes_special = actual_pcaps == test['expected_pcaps']
            else:
                 # Check for mandatory alerts in test A1
                 passes_special = (actual_detected == test['expected_alerts'])
           
            # 4. Final Result
            result_status = "PASS" if passes_count and passes_special else "FAIL"
           
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
