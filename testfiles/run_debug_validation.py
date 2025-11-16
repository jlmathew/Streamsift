#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  @file      run_debug_validation.py
#  @version   1.1.0 (Deep Inspection & Comparison)
#  @brief     Compares J0/J4. Inspects input PCAPs on failure to print values.
# =============================================================================

import subprocess
import os
import glob
import json
import sys
import struct

BINARY = "./streamsift"
DATA_DIR = "./debug_data"
MANIFEST = os.path.join(DATA_DIR, "debug_manifest.json")

def clean_output(prefix):
    for f in glob.glob(f"{prefix}*"): os.remove(f)

def get_pcap_pkt_count(path):
    try:
        # Fast raw count of pcap headers
        with open(path, 'rb') as f:
            f.read(24) # Global Header
            cnt = 0
            while True:
                hdr = f.read(16)
                if len(hdr) < 16: break
                caplen = int.from_bytes(hdr[8:12], 'little')
                f.seek(caplen, 1)
                cnt += 1
            return cnt
    except: return 0

def extract_sni_from_pcap_bytes(path):
    """Simple heuristic to extract SNI string for debug printing"""
    try:
        with open(path, 'rb') as f:
            raw = f.read()
            # Look for google.com or yahoo.com pattern
            if b"google.com" in raw: return "google.com"
            if b"yahoo.com" in raw: return "yahoo.com"
            return "Unknown/None"
    except: return "Error"

def main():
    if not os.path.exists(MANIFEST):
        print("Run generate_debug_test.py first.")
        sys.exit(1)
   
    with open(MANIFEST) as f: tests = json.load(f)
   
    print(f"{'TEST ID':<10} | {'MODE':<4} | {'RES':<4} | {'FILES':<5} | {'DETAILS'}")
    print("-" * 80)

    for t in tests:
        tid = t['id']
        prefix = os.path.join(DATA_DIR, f"out_{tid}")
       
        results = {}
       
        # Run both modes
        for j in [0, 4]:
            clean_output(f"{prefix}_j{j}")
            cmd = [BINARY, "-r", os.path.join(DATA_DIR, t['pcap']), "-n", f"{prefix}_j{j}", "-j", str(j)] + t['args']
           
            # Run Binary
            subprocess.run(cmd, capture_output=True, timeout=10)
           
            # Count Saved Files
            files = sorted(glob.glob(f"{prefix}_j{j}*.pcap"))
            results[j] = files
       
        # Compare
        count_j0 = len(results[0])
        count_j4 = len(results[4])
        exp = t['exp_saves']
       
        # Evaluate J0
        status0 = "PASS" if count_j0 == exp else "FAIL"
        status4 = "PASS" if count_j4 == exp else "FAIL"
       
        # Details Logic
        detail0 = ""
        detail4 = ""

        # Check Packet Counts for Buffer Test
        if t['check'] == "SIZE_CHECK":
            for p in results[0]:
                if get_pcap_pkt_count(p) != t['meta']['expected_pkts']:
                    status0 = "FAIL"; detail0 = f"Bad Pkt Cnt {get_pcap_pkt_count(p)}"
            for p in results[4]:
                if get_pcap_pkt_count(p) != t['meta']['expected_pkts']:
                    status4 = "FAIL"; detail4 = f"Bad Pkt Cnt {get_pcap_pkt_count(p)}"

        # Check Values for SNI Test (Inspect Input vs Output)
        if t['check'] == "VAL_CHECK":
            # If we missed hits, verify what was in the files we DID save
            # Or just report count mismatch
            if status0 == "FAIL":
                detail0 = f"Exp {exp}, Got {count_j0}. "
            if status4 == "FAIL":
                detail4 = f"Exp {exp}, Got {count_j4}. "

        # Report J0
        print(f"{tid:<10} | J0   | {status0:<4} | {count_j0:<5} | {detail0}")
       
        # Report J4
        diff_msg = ""
        if count_j0 != count_j4:
            diff_msg = f" [DIFF! J0={count_j0}]"
        print(f"{tid:<10} | J4   | {status4:<4} | {count_j4:<5} | {detail4}{diff_msg}")
        print("-" * 80)

if __name__ == "__main__":
    main()
	

