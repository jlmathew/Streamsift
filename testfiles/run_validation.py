#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  @file      run_validation.py
#  @author    James Mathewson
#  @version   1.3.0 (Added Debug Correlation)
#  @brief     Validates output and correlates stream-to-thread assignment.
# =============================================================================

import logging
import subprocess
import os
import glob as pyglob
import time
import shlex
import json
import re

# --- Configuration ---
BINARY_PATH = "./streamsift"
OUTPUT_DIR = "./test_data"
MANIFEST_FILE = os.path.join(OUTPUT_DIR, "tests_manifest.json")

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Regex to parse C++ Debug Output
# Example: [LOG] STREAM_DEBUG key=080006... thread=1 pkts=50 saved=1
DEBUG_REGEX = re.compile(r"STREAM_DEBUG key=([0-9A-F]+) thread=(\d+) pkts=(\d+) saved=(\d+)")

def parse_stream_debug(stdout_text):
    """
    Parses the stdout for STREAM_DEBUG lines.
    Returns a dict: { 'key_hex': [ {thread: int, pkts: int, saved: bool}, ... ] }
    """
    correlation = {}
    for line in stdout_text.splitlines():
        match = DEBUG_REGEX.search(line)
        if match:
            key = match.group(1)
            thread_id = int(match.group(2))
            pkts = int(match.group(3))
            saved = (match.group(4) == "1")
           
            if key not in correlation:
                correlation[key] = []
            correlation[key].append({'thread': thread_id, 'pkts': pkts, 'saved': saved})
    return correlation

def analyze_correlation(correlation, test_id, mode_label):
    """
    Checks for split streams (same key on multiple threads).
    Prints a report if issues found.
    """
    issues_found = False
    total_unique_streams = len(correlation)
   
    for key, occurrences in correlation.items():
        threads_seen = set(o['thread'] for o in occurrences)
        total_pkts = sum(o['pkts'] for o in occurrences)
       
        # Check 1: Split Stream (Critical for hashing issues)
        if len(threads_seen) > 1:
            logger.error(f"[{mode_label}] CRITICAL: Stream Split! Key={key} seen on threads {threads_seen}. Total Pkts={total_pkts}")
            issues_found = True
           
        # Check 2: Fragmentation (Same key, same thread, but multiple objects created?)
        # This happens if C++ destroys/recreates stream object incorrectly
        if len(occurrences) > 1 and len(threads_seen) == 1:
             logger.warning(f"[{mode_label}] WARNING: Stream Fragmented on single thread. Key={key} instances={len(occurrences)}")

    if issues_found:
        logger.info(f"[{mode_label}] Debug Dump: {total_unique_streams} unique keys seen.")
   
    return not issues_found

def run_test(test):
    test_id = test['id']
    prefix = os.path.join(OUTPUT_DIR, f"out_{test_id}")
    pcap = test['pcap_file']
   
    # Clean previous output files
    for f in pyglob.glob(f"{prefix}_*"): os.remove(f)
   
    results = {}
   
    for threads in test['test_modes']:
        mode_label = f"J{threads}"
       
        # Build command
        cmd = [BINARY_PATH, "-r", pcap, "-n", prefix, "-j", str(threads)] + test['cli_args']
        cmd_str = ' '.join(shlex.quote(arg) for arg in cmd)
        logger.info(f"[{mode_label}] CMD: {cmd_str}")

        try:
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
           
            # --- ANALYZE OUTPUT ---
            correlation = parse_stream_debug(process.stdout)
            consistency_pass = analyze_correlation(correlation, test_id, mode_label)
           
            # Wait for IO
            time.sleep(0.5)
            actual_pcaps = len(pyglob.glob(f"{prefix}_*.pcap"))
            actual_detected = len(pyglob.glob(f"{prefix}_*.detected"))

            # Validation Logic
            passes_count = (actual_pcaps == test['expected_pcaps'])
           
            if test['check_type'] == "TRUNCATION":
                 passes_special = actual_pcaps == test['expected_pcaps']
            else:
                 passes_special = (actual_detected == test['expected_alerts'])
           
            passes_all = passes_count and passes_special and consistency_pass
           
            result_status = "PASS" if passes_all else "FAIL"
           
            if result_status == "PASS":
                logger.info(f"[{mode_label}] RESULT: PASS (Saved: {actual_pcaps}, Unique Keys: {len(correlation)})")
            else:
                logger.error(f"[{mode_label}] RESULT: FAIL (Exp: {test['expected_pcaps']}, Got: {actual_pcaps}). Hash Consistency: {consistency_pass}")
           
            results[mode_label] = result_status
           
        except subprocess.TimeoutExpired:
            logger.error(f"[{mode_label}] TIMEOUT expired!")
            results[mode_label] = "TIMEOUT"
           
    return results

if __name__ == '__main__':
    if not os.path.exists(MANIFEST_FILE):
        logger.error(f"Manifest not found. Run generate_test_pcaps.py first.")
        exit(1)
    with open(MANIFEST_FILE, 'r') as f: manifest = json.load(f)
   
    full_report = {}
    print(f"\n--- Starting StreamSift Validation ({len(manifest)} Scenarios) ---")
    for test in manifest:
        full_report[test['id']] = run_test(test)
       
    print("\n\n=== FINAL TEST SUMMARY ===")
    total_tests = 0; passed_tests = 0
    for test_id, results in full_report.items():
        for mode, status in results.items():
            total_tests += 1
            if status == "PASS": passed_tests += 1
            print(f"| {test_id:<15} | {mode:<5} | {status:<7} |")
    print(f"\nOverall Score: {passed_tests} / {total_tests} Tests Passed.")
