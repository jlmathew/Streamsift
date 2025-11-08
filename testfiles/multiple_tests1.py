#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  @file      run_all_tests.py
#  @author    James Mathewson
#  @version   0.9.7 beta
#  @brief     Automated end-to-end test harness for the StreamSift C++ engine.
#             Generates PCAPs using Scapy, runs the binary, and verifies output.
# =============================================================================

import logging
import random
import subprocess
import os
import glob as pyglob
import shutil
import time
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, GRE

# --- Configuration ---
BINARY_PATH = "./streamsift"
OUTPUT_DIR = "./test_output"
BASE_TIME = 1700000000.0

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# ==========================================
# 1. PACKET GENERATORS
# ==========================================
def create_tcp_stream(src_ip, dst_ip, src_port, dst_port,
                      pkt_count=50, start_time=BASE_TIME,
                      handshake=True, anomaly="NONE", encapsulation="NONE",
                      special_ttl=64, special_inner_ttl=64):
    pkts = []
    t = start_time + random.uniform(0, 0.1) # Less random start time
    seq = 10000
    ack = 0
   
    def wrap(inner_pkt):
        eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        if encapsulation == "NONE": return eth/inner_pkt
        if encapsulation == "GRE":
            return eth/IP(src="10.0.0.1", dst="10.0.0.2", proto=47, ttl=special_ttl)/GRE(proto=0x0800)/inner_pkt
        if encapsulation == "IPIP":
            return eth/IP(src="10.0.0.1", dst="10.0.0.2", proto=4, ttl=special_ttl)/inner_pkt
        return eth/inner_pkt

    if handshake and anomaly != "MISSING_SYN":
         p = wrap(IP(src=src_ip, dst=dst_ip, ttl=special_inner_ttl)/TCP(sport=src_port, dport=dst_port, flags='S', seq=seq))
         p.time = t; pkts.append(p); t += 0.01; seq += 1
         ack = 50000
         p = wrap(IP(src=dst_ip, dst=src_ip, ttl=64)/TCP(sport=dst_port, dport=src_port, flags='SA', seq=ack, ack=seq))
         p.time = t; pkts.append(p); t += 0.01; ack += 1
         p = wrap(IP(src=src_ip, dst=dst_ip, ttl=special_inner_ttl)/TCP(sport=src_port, dport=dst_port, flags='A', seq=seq, ack=ack))
         p.time = t; pkts.append(p); t += 0.01
    elif anomaly == "MISSING_SYN":
         ack = 50000

    for i in range(pkt_count):
        # Deterministic direction to avoid noise
        if i % 2 == 0:
             s, d, sp, dp, c_seq, c_ack, flags, ttl = src_ip, dst_ip, src_port, dst_port, seq, ack, 'PA', special_inner_ttl
        else:
             s, d, sp, dp, c_seq, c_ack, flags, ttl = dst_ip, src_ip, dst_port, src_port, ack, seq, 'A', 64
       
        # --- FIX: Deterministic Anomaly Injection ---
        win = 65535
        if anomaly == "SMALL_WINDOW" and i == 10: win = 500 # Always happen at packet 10
        if anomaly == "SYN_FIN" and i == 10: flags = "SF"
        if anomaly == "RST_FIN" and i == 10: flags = "RF"
        # --------------------------------------------

        p = wrap(IP(src=s, dst=d, ttl=ttl)/TCP(sport=sp, dport=dp, flags=flags, seq=c_seq, ack=c_ack, window=win)/Raw(load=f"d{i}"))
        p.time = t; pkts.append(p); t += 0.005
        if s == src_ip: seq += 2
        else: ack += 2

    if anomaly == "RST_END":
        p = wrap(IP(src=src_ip, dst=dst_ip, ttl=special_inner_ttl)/TCP(sport=src_port, dport=dst_port, flags='R', seq=seq, ack=ack))
        p.time = t; pkts.append(p)

    return pkts

# ==========================================
# 2. TEST SCENARIOS
# ==========================================
def gen_test1(fname):
    pkts = []
    for i in range(10): pkts.extend(create_tcp_stream(f"10.1.1.{i}", "8.8.8.8", 50000+i, 80, anomaly="NONE"))
    for i in range(10, 20): pkts.extend(create_tcp_stream(f"10.1.1.{i}", "8.8.8.8", 50000+i, 80, anomaly="RST_END"))
    return pkts

def gen_test3(fname):
    pkts = []
    for i in range(45): pkts.extend(create_tcp_stream(f"10.3.3.{i}", "8.8.8.8", 40000+i, 443, anomaly="NONE"))
    for i in range(45, 50): pkts.extend(create_tcp_stream(f"10.3.3.{i}", "8.8.8.8", 40000+i, 443, anomaly="SMALL_WINDOW"))
    return pkts

def gen_test4(fname):
    pkts = []
    for i in range(10): pkts.extend(create_tcp_stream(f"172.16.1.{i}", "192.168.1.1", 10000+i, 80, encapsulation="GRE", anomaly="RST_END"))
    for i in range(10, 20): pkts.extend(create_tcp_stream(f"172.16.2.{i}", "192.168.1.1", 20000+i, 80, encapsulation="IPIP", anomaly="RST_END"))
    return pkts

def gen_test6(fname):
    pkts = []
    for i in range(10): pkts.extend(create_tcp_stream(f"10.6.1.{i}", "8.8.8.8", 50000+i, 443, anomaly="NONE"))
    for i in range(10, 15): pkts.extend(create_tcp_stream(f"10.6.1.{i}", "8.8.8.8", 50000+i, 443, handshake=False, anomaly="SYN_FIN"))
    for i in range(15, 20): pkts.extend(create_tcp_stream(f"10.6.1.{i}", "8.8.8.8", 50000+i, 443, handshake=False, anomaly="RST_FIN"))
    return pkts

def gen_test10(fname):
    pkts = []
    for i in range(10): pkts.extend(create_tcp_stream(f"10.10.1.{i}", "1.1.1.1", 50000+i, 80, encapsulation="GRE", special_ttl=64, special_inner_ttl=64, anomaly="RST_END"))
    for i in range(10, 20): pkts.extend(create_tcp_stream(f"10.10.2.{i}", "1.1.1.1", 50000+i, 80, encapsulation="GRE", special_ttl=1, special_inner_ttl=64, anomaly="RST_END"))
    for i in range(20, 30): pkts.extend(create_tcp_stream(f"10.10.3.{i}", "1.1.1.1", 50000+i, 80, encapsulation="GRE", special_ttl=64, special_inner_ttl=1, anomaly="RST_END"))
    return pkts

def gen_test11(fname):
    pkts = []
    # Always add Ether header
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    for i in range(10):
        p = eth/IP(src=f"10.11.1.{i}", dst="8.8.8.8")/TCP(sport=50000+i, dport=80, flags='S')
        p.time = BASE_TIME
        pkts.append(p)
   
    p = eth/IP(src="1.1.1.1", dst="2.2.2.2")/UDP(sport=53, dport=53)
    p.time = BASE_TIME + 601.0
    pkts.append(p)
    return pkts

def gen_test13(fname):
    pkts = []
    # Always add Ether header
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    for i in range(5):
        p = eth/IPv6(src=f"2001:db8::{i}", dst="2001:db8::ffff", nh=4)/IP(src="1.1.1.1", dst="2.2.2.2", proto=4, ttl=10)/IP(src="3.3.3.3", dst="4.4.4.4", proto=17, ttl=20)/UDP(sport=53, dport=53)/Raw(load=f"match{i}")
        p.time = BASE_TIME + i*0.1
        pkts.append(p)
    for i in range(5, 10):
        p = eth/IPv6(src=f"2001:db8::{i}", dst="2001:db8::ffff", nh=4)/IP(src="1.1.1.1", dst="2.2.2.2", proto=4, ttl=10)/IP(src="3.3.3.3", dst="4.4.4.4", proto=17, ttl=64)/UDP(sport=53, dport=53)/Raw(load=f"noise{i}")
        p.time = BASE_TIME + i*0.1
        pkts.append(p)
    return pkts

def gen_test14(fname):
    pkts = []
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    c_ip, s_ip = "10.14.0.1", "10.14.0.2"
    for i in range(6):
        p = eth/IP(src=c_ip, dst=s_ip)/TCP(sport=50000, dport=80, seq=1000+i, flags='A')
        p.time = BASE_TIME+i
        pkts.append(p)
    for i in range(50):
        p = eth/IP(src=s_ip, dst=c_ip)/TCP(sport=80, dport=50000, seq=5000+i, flags='A')
        p.time = BASE_TIME+5.1+(i*0.001)
        pkts.append(p)
   
    p = eth/IP(src=c_ip, dst=s_ip)/TCP(sport=50000, dport=80, seq=2000, flags='PA', window=9999)
    p.time = BASE_TIME+6.0
    pkts.append(p)
    return pkts

# ==========================================
# 3. TEST HARNESS
# ==========================================
TESTS = [
        {"id": 1, "name": "Basic RST Save", "gen": gen_test1, "args": ["-t", '"TCP.IsSyn()"', "-p", '"TCP.IsRst()"', "-d", "true"], "expected_files": 10, "desc": "Should save 10 streams and create 10 .detected files."},
    {"id": 3, "name": "Arithmetic Filter", "gen": gen_test3, "args": ["-t", '"TCP.WindowSize() < 1000"'], "expected_files": 5},
    {"id": 4, "name": "GRE/IPIP Encap", "gen": gen_test4, "args": ["-p", '"TCP.IsRst()"'], "expected_files": 20},
    {"id": 6, "name": "Complex Boolean", "gen": gen_test6, "args": ["-t", '"(TCP.IsSyn() AND TCP.IsFin()) OR (TCP.IsRst() AND TCP.IsFin())"'], "expected_files": 10},
    {"id": 10, "name": "Layer Specificity", "gen": gen_test10, "args": ["-t", '"IP.TTL(2) < 5"'], "expected_files": 10},
    {"id": 11, "name": "Timeout Deletion", "gen": gen_test11, "args": ["-t", '"TCP.IsSyn()"', "-p", '"TCP.IsRst()"', "-c", "timeouts.conf"], "expected_files": 0},
    {"id": 13, "name": "Ultra-Deep Encap", "gen": gen_test13, "args": ["-t", '"IP.TTL(2) == 20"'], "expected_files": 5},
    {"id": 14, "name": "Directional Buffers", "gen": gen_test14, "args": ["-t", '"TCP.WindowSize() == 9999"', "-M", "separate", "-b", "10"], "expected_files": 2}
]

def run_tests():
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    # Create a dummy timeouts.conf for Test 11
    with open("timeouts.conf", "w") as f: f.write("DEFAULT=1\nTCP=1\nUDP=1\n")

    results = {}
    for test in TESTS:
        print(f"\n=== TEST {test['id']}: {test['name']} ===")
        pcap = os.path.join(OUTPUT_DIR, f"test{test['id']}.pcap")
        prefix = os.path.join(OUTPUT_DIR, f"out{test['id']}")
       
        # Force regenerate every time to be safe
        if os.path.exists(pcap): os.remove(pcap)
       
        logger.info("Generating PCAP...")
        pkts = test['gen'](pcap)
        if test['id'] != 14: pkts.sort(key=lambda x: x.time)
        wrpcap(pcap, pkts)
           
        for f in pyglob.glob(f"{prefix}_*.pcap"): os.remove(f)
        for f in pyglob.glob(f"{prefix}_*.detected"): os.remove(f)

        cmd = [BINARY_PATH, "-r", pcap, "-j 0 -n", prefix] + test['args']
        logger.info(f"CMD: {' '.join(cmd)}")
        try:
            # Increased timeout for larger tests
            subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            logger.error("TIMEOUT")
            results[test['id']] = False
            continue

        actual_files = len(pyglob.glob(f"{prefix}_*.pcap"))
        # Special check for Test 1
        actual_pcap = len(pyglob.glob(f"{prefix}_*.pcap"))
        actual_detected=len(pyglob.glob(f"{prefix}_*.detected"))
        if test['id'] == 1:
            if actual_pcap == 10 and actual_detected == 10:
                res = "PASS"
            else:
                res = f"FAIL (Pcaps: {actual_pcap}, Detected: {actual_detected})"
        else:
            res = "PASS" if actual_files == test['expected_files'] else f"FAIL (Got {actual_files})"
        logger.info(f"RESULT: {res}")
        results[test['id']] = (res == "PASS")

    print("\n=== SUMMARY ===")
    for id, passed in results.items(): print(f"Test {id:2d}: {'PASS' if passed else 'FAIL'}")

if __name__ == '__main__':
    run_tests()
