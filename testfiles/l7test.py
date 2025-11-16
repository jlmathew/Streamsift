#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  @file      run_protocol_tests.py
#  @author    James Mathewson
#  @version   1.1.0 alpha
#  @brief     Test harness for L7 protocols (DNS, TLS, SMB).
#             UPDATED: Added Test L7_6 for TLS SNI String Matching.
# =============================================================================

import logging, random, subprocess, os, glob as pyglob, shutil, time, shlex, struct
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR

BINARY_PATH = "./streamsift"
OUTPUT_DIR = "./test_output_l7"
BASE_TIME = 1700000000.0
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

def force_build(pkt): return pkt.__class__(bytes(pkt))

# --- L7 PACKET GENERATORS ---

def gen_dns_test(fname):
    logger.info(f"Generating DNS test: {fname}")
    pkts = []
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    for i in range(5):
        p = eth/IP(src=f"10.1.1.{i}", dst="8.8.8.8")/UDP(sport=50000+i, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
        p.time = BASE_TIME + i*0.1; pkts.append(force_build(p))
    for i in range(5, 10):
        p = eth/IP(src=f"10.1.1.{i}", dst="8.8.8.8")/UDP(sport=50000+i, dport=5353)/DNS(rd=1, qd=DNSQR(qname="local.lan"))
        p.time = BASE_TIME + i*0.1; pkts.append(force_build(p))
    wrpcap(fname, pkts)

def gen_tls_test(fname):
    logger.info(f"Generating TLS Handshake test: {fname}")
    pkts = []
    eth = Ether()
    for i in range(5):
        tls_header = b'\x16\x03\x03\x00\x30'
        handshake_header = b'\x01\x00\x00\x2C' + (b'\x00' * 44)
        p = eth/IP(src=f"10.2.2.{i}", dst="1.1.1.1")/TCP(sport=40000+i, dport=443, flags='PA')/Raw(load=tls_header + handshake_header)
        p.time = BASE_TIME + i*0.1; pkts.append(force_build(p))
    wrpcap(fname, pkts)

def gen_smb_test(fname):
    logger.info(f"Generating SMB test: {fname}")
    pkts = []
    eth = Ether()
    for i in range(5):
        nbss = b'\x00\x00\x00\x40'
        smb2_header = b'\xFE\x53\x4D\x42' + (b'\x00' * 8) + b'\x00\x00' + (b'\x00' * 50)
        p = eth/IP(src=f"192.168.1.{i}", dst="192.168.1.100")/TCP(sport=50000+i, dport=445, flags='PA')/Raw(load=nbss + smb2_header)
        p.time = BASE_TIME + i*0.1; pkts.append(force_build(p))
    wrpcap(fname, pkts)

def gen_tls_heuristic_test(fname):
    logger.info(f"Generating TLS Heuristic test: {fname}")
    pkts = []
    eth = Ether()
    for i in range(5):
        tls_header = b'\x16\x03\x03\x00\x30'
        handshake_header = b'\x01\x00\x00\x2C' + (b'\x00' * 44)
        p = eth/IP(src=f"10.4.4.{i}", dst="1.1.1.1")/TCP(sport=30000+i, dport=8443, flags='PA')/Raw(load=tls_header + handshake_header)
        p.time = BASE_TIME + i*0.1; pkts.append(force_build(p))
    wrpcap(fname, pkts)

def gen_tls_truncation_test(fname):
    logger.info(f"Generating TLS Truncation test: {fname}")
    pkts = []
    eth = Ether()
    app_data = b'\x17\x03\x03\x01\xf4' + (b'A' * 500)
    for i in range(5):
        p = eth/IP(src=f"10.5.5.{i}", dst="1.1.1.1")/TCP(sport=40000+i, dport=443, flags='PA')/Raw(load=app_data)
        p.time = BASE_TIME + i*0.1; pkts.append(force_build(p))
    wrpcap(fname, pkts)

# --- NEW SNI TEST GENERATOR ---
def gen_tls_sni_test(fname):
    logger.info(f"Generating TLS SNI test: {fname}")
    pkts = []
    eth = Ether()
   
    def build_sni_packet(src_ip, sni_string):
        sni_bytes = sni_string.encode()
        sni_len = len(sni_bytes)
        # Using struct.pack to ensure Big Endian (Network Order) packing
        # ExtType(2)=0x0000, ExtLen(2)=5+len, ListLen(2)=3+len, NameType(1)=0, NameLen(2), Name
        ext_data = struct.pack(f"!HHHB H{sni_len}s",
            0x0000, sni_len + 5, sni_len + 3, 0x00, sni_len, sni_bytes)

        # Random (32), SessID(0)
        random_bytes = b'\xAA' * 32
        # Ciphers (2 bytes len + 2 bytes data)
        ciphers = b'\x00\x02\x00\x2F'
       
        # Handshake body: Ver(2) + Random(32) + SessID(1) + Ciphers + Comp(1) + ExtLen(2) + ExtData
        handshake_body = b'\x03\x03' + random_bytes + b'\x00' + ciphers + b'\x01\x00' + struct.pack("!H", len(ext_data)) + ext_data
       
        # Handshake Header: Type(1) + Length(3)
        hs_type = b'\x01'
        hs_len = struct.pack("!I", len(handshake_body))[1:] # take last 3 bytes
       
        full_handshake = hs_type + hs_len + handshake_body
       
        # TLS Record Header: Type(1)=0x16, Ver(2)=0x0301, Len(2)
        rec_header = b'\x16\x03\x01' + struct.pack("!H", len(full_handshake))
       
        return eth/IP(src=src_ip, dst="1.1.1.1")/TCP(sport=50000, dport=443, flags='PA')/Raw(load=rec_header + full_handshake)

    # 5 Matches ("google.com") -> SAVE
    for i in range(5):
        p = build_sni_packet(f"10.6.6.{i}", "google.com")
        p.time = BASE_TIME + i*0.1
        pkts.append(force_build(p))

    # 5 Non-Matches ("yahoo.com") -> DISCARD
    for i in range(5, 10):
        p = build_sni_packet(f"10.6.6.{i}", "yahoo.com")
        p.time = BASE_TIME + i*0.1
        pkts.append(force_build(p))

    wrpcap(fname, pkts)

TESTS = [
    {"id": "L7_1", "name": "DNS Queries", "gen": gen_dns_test, "args": ["-t", "DNS.IsQuery()", "--dns-ports", "53,5353"], "expected": 10},
    {"id": "L7_2", "name": "TLS Handshakes", "gen": gen_tls_test, "args": ["-t", "TLS.IsHandshake()"], "expected": 5},
    {"id": "L7_3", "name": "SMB Negotiate", "gen": gen_smb_test, "args": ["-t", "SMB.Command() == 0"], "expected": 5},
    {"id": "L7_4", "name": "TLS Heuristic", "gen": gen_tls_heuristic_test, "args": ["-t", "TLS.IsHandshake()"], "expected": 5},
    {"id": "L7_5", "name": "TLS Truncation", "gen": gen_tls_truncation_test, "args": ["-t", "TCP.DstPort() == 443", "-T", "true"], "expected": 5, "check_truncation": True},
    {"id": "L7_6", "name": "TLS SNI String Match", "gen": gen_tls_sni_test, "args": ["-t", 'TLS.Sni() == "google.com"'], "expected": 5}
]

def run_tests():
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    with open("timeouts.conf", "w") as f: f.write("DEFAULT=1\n")
    print("\n=== L7 PROTOCOL TESTS ===")
    for test in TESTS:
        pcap = os.path.join(OUTPUT_DIR, f"{test['id']}.pcap")
        prefix = os.path.join(OUTPUT_DIR, f"out_{test['id']}")
       
        if not os.path.exists(pcap):
            test['gen'](pcap)
        for f in pyglob.glob(f"{prefix}_*"): os.remove(f)

        cmd = [BINARY_PATH, "-r", pcap, "-n", prefix, "-j", "0", "-c", "timeouts.conf"] + test['args']
        logger.info(f"CMD: {' '.join(shlex.quote(arg) for arg in cmd)}")
       
        try: subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except: pass
        time.sleep(1.0)
       
        actual = len(pyglob.glob(f"{prefix}_*.pcap"))
       
        if test.get('check_truncation'):
             is_small = True
             for p in pyglob.glob(f"{prefix}_*.pcap"):
                 if os.path.getsize(p) > 200: is_small = False
             res = "PASS" if actual == test['expected'] and is_small else f"FAIL (Got {actual})"
        else:
             res = "PASS" if actual == test['expected'] else f"FAIL (Got {actual})"
        print(f"Test {test['id']:4s}: {res}")

if __name__ == '__main__':
    run_tests()
