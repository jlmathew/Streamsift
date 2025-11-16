#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  @file      generate_test_pcaps.py
#  @author    James Mathewson
#  @version   1.2.2 alpha (Final Scapy Time Fix)
#  @brief     Generates all synthetic PCAP files and the corresponding JSON manifest.
# =============================================================================

import logging
import random
import os
import struct
import json
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR

# --- Configuration ---
OUTPUT_DIR = "./test_data"
MANIFEST_FILE = "tests_manifest.json"
BASE_TIME = 1700000000.0
# Ensure directories exist
os.makedirs(OUTPUT_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

def force_build(pkt):
    """Forces Scapy to build the packet (calculating lengths and checksums)"""
    return pkt.__class__(bytes(pkt))

# ==========================================
# 1. CORE PACKET GENERATORS
# ==========================================

def create_tcp_stream(id_start, num_streams, src_ip_base, dst_ip, start_time, anomaly="NONE", encapsulation="NONE", pkt_count=50, special_ttl=64, special_inner_ttl=64):
    """Generates N streams with a specific anomaly."""
    all_pkts = []
   
    for i in range(num_streams):
        stream_id = id_start + i
        src_ip = f"{src_ip_base}.{stream_id}"
        src_port = 50000 + stream_id
        dst_port = 80 if anomaly != "TLS" else 443

        t = start_time + random.uniform(0, 0.1)
        seq = 10000; ack = 50000
       
        def wrap(inner_pkt, ttl=special_ttl):
            eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            if encapsulation == "NONE": return eth/inner_pkt
            if encapsulation == "GRE": return eth/IP(src="10.0.0.1", dst="10.0.0.2", proto=47, ttl=ttl)/GRE(proto=0x0800)/inner_pkt
            return eth/IP(src="10.0.0.1", dst="10.0.0.2", proto=4, ttl=ttl)/inner_pkt # IPIP

        # Handshake
        p = wrap(IP(src=src_ip, dst=dst_ip, ttl=special_inner_ttl)/TCP(sport=src_port, dport=dst_port, flags='S', seq=seq))
        p.time = t; all_pkts.append(force_build(p)); t += 0.01; seq += 1
        p = wrap(IP(src=dst_ip, dst=src_ip, ttl=64)/TCP(sport=dst_port, dport=src_port, flags='SA', seq=ack, ack=seq))
        p.time = t; all_pkts.append(force_build(p)); t += 0.01; ack += 1
        p = wrap(IP(src=src_ip, dst=dst_ip, ttl=special_inner_ttl)/TCP(sport=src_port, dport=dst_port, flags='A', seq=seq, ack=ack))
        p.time = t; all_pkts.append(force_build(p)); t += 0.01

        for i in range(pkt_count):
            s, d, sp, dp, c_seq, c_ack, flags = src_ip, dst_ip, src_port, dst_port, seq, ack, 'PA'
            win = 65535
           
            if anomaly == "SMALL_WINDOW" and i == 10: win = 500
            if anomaly == "SYN_FIN" and i == 10: flags = "SF"
           
            p = wrap(IP(src=s, dst=d, ttl=special_inner_ttl)/TCP(sport=sp, dport=dp, flags=flags, seq=c_seq, ack=c_ack, window=win)/Raw(load=f"d{i}"))
            p.time = t; all_pkts.append(force_build(p)); t += 0.005
            if s == src_ip: seq += 2
            else: ack += 2

        if anomaly == "RST_END":
            p = wrap(IP(src=src_ip, dst=dst_ip, ttl=special_inner_ttl)/TCP(sport=src_port, dport=dst_port, flags='R', seq=seq, ack=ack))
            p.time = t; all_pkts.append(force_build(p))
           
    return all_pkts

def create_raw_dns_packet(is_query, src_ip, dst_ip, src_port, dst_port, qname="test.local"):
    eth = Ether()
    dns_layer = DNS(rd=1, qd=DNSQR(qname=qname))
    if not is_query:
         dns_layer.qr = 1
         dns_layer.an = DNSRR(rrname=qname, rdata="1.2.3.4")
   
    pkt = eth/IP(src=src_ip, dst=dst_ip)/UDP(sport=src_port, dport=dst_port)/dns_layer
    pkt.time = BASE_TIME + random.uniform(0, 0.1)
    return force_build(pkt)

def create_raw_tls_sni(src_ip, sni_string, dst_port=443):
    eth = Ether()
    sni_bytes = sni_string.encode()
    ext_data = struct.pack(f"!HHHB H{len(sni_bytes)}s",
        0x0000, len(sni_bytes) + 5, len(sni_bytes) + 3, 0x00, len(sni_bytes), sni_bytes)
   
    handshake_body = b'\x03\x03' + (b'\xAA' * 32) + b'\x00' + b'\x00\x02\x00\x2F' + b'\x01\x00' + struct.pack("!H", len(ext_data)) + ext_data
    hs_type = b'\x01'
    hs_len = struct.pack("!I", len(handshake_body))[1:]
    full_handshake = hs_type + hs_len + handshake_body
    rec_header = b'\x16\x03\x01' + struct.pack("!H", len(full_handshake))
   
    pkt = eth/IP(src=src_ip, dst="1.1.1.1")/TCP(sport=50000, dport=dst_port, flags='PA')/Raw(load=rec_header + full_handshake)
    pkt.time = BASE_TIME + random.uniform(0, 0.1)
    return force_build(pkt)


# ==========================================
# 2. TEST DEFINITIONS & MANIFEST WRITING
# ==========================================

TEST_MANIFEST = []

def add_test(test_id, name, streams, expected_saves, cli_args, check_type="PCAPS", expected_alerts=0):
    global TEST_MANIFEST
   
    # 1. Write the PCAP file
    pcap_path = os.path.join(OUTPUT_DIR, f"{test_id}.pcap")
    streams.sort(key=lambda x: x.time)
    wrpcap(pcap_path, streams)

    # 2. Add entry to manifest
    TEST_MANIFEST.append({
        "id": test_id,
        "name": name,
        "pcap_file": pcap_path,
        "total_streams": len(set([f"{p[IP].src}:{p[TCP].sport}->{p[IP].dst}:{p[TCP].dport}" if TCP in p else f"{p[IP].src}->{p[IP].dst}" for p in streams if IP in p])),
        "cli_args": cli_args,
        "expected_pcaps": expected_saves,
        "expected_alerts": expected_alerts if cli_args.count("-d") > 0 else 0,
        "check_type": check_type, # PCAPS, TRUNCATION, NONE
        "test_modes": [0, 4] # Single-thread and 4-thread
    })
    logger.info(f"Generated {test_id}: {expected_saves} expected saves.")

# --- SCENARIO GENERATION ---

# A. Simple Functional Tests (Single Feature Validation)
# =====================================================
streams_a1 = create_tcp_stream(1, 10, "10.1.1", "8.8.8.8", BASE_TIME, anomaly="NONE")
streams_a1.extend(create_tcp_stream(11, 10, "10.1.1", "8.8.8.8", BASE_TIME, anomaly="RST_END"))
add_test("A1_RST_SAVE", "L4: Basic RST Filter", streams_a1, 10, ["-t", "TCP.IsSyn()", "-p", "TCP.IsRst()", "-d", "true"], expected_alerts=10)

# A2: Arithmetic/Window Filter (Expected 5 saves)
streams_a2 = create_tcp_stream(1, 45, "10.2.1", "8.8.8.8", BASE_TIME, anomaly="NONE")
streams_a2.extend(create_tcp_stream(46, 5, "10.2.1", "8.8.8.8", BASE_TIME, anomaly="SMALL_WINDOW"))
add_test("A2_WIN_FILTER", "L4: Window Size Filter", streams_a2, 5, ["-t", "TCP.WindowSize() < 1000"])

# B. L7 Protocol Tests
# =====================================================
# B1: DNS Queries (Expected 10 saves: 5 on 53, 5 on 5353)
streams_b1 = []
streams_b1.extend([create_raw_dns_packet(True, f"10.3.1.{i}", "8.8.8.8", 50000+i, 53, f"std-{i}.com") for i in range(5)])
streams_b1.extend([create_raw_dns_packet(True, f"10.3.1.{i}", "8.8.8.8", 50010+i, 5353, f"custom-{i}.com") for i in range(5, 10)])
streams_b1.extend([create_raw_dns_packet(False, "8.8.8.8", f"10.3.1.{i}", 53, 50020+i, f"response-{i}.com") for i in range(10, 15)])
add_test("B1_DNS_PORT", "L7: DNS Query + Custom Ports", streams_b1, 10, ["-t", "DNS.IsQuery()", "--dns-ports", "53,5353"])

# B2: TLS SNI String Matching (Expected 5 saves: only "google.com")
streams_b2 = [create_raw_tls_sni(f"10.4.1.{i}", "google.com") for i in range(5)]
streams_b2.extend([create_raw_tls_sni(f"10.4.1.{i}", "yahoo.com") for i in range(5, 10)])
add_test("B2_TLS_SNI", "L7: TLS SNI String Match", streams_b2, 5, ["-t", 'TLS.Sni() == "google.com"'])

# B3: TLS Truncation (Expected 5 saves, output files must be small)
streams_b3 = []
for i in range(5):
    tls_header = b'\x17\x03\x03\x01\xf4'
    payload = b'A' * 500
    p = Ether()/IP(src=f"10.5.1.{i}", dst="1.1.1.1")/TCP(sport=40000+i, dport=443, flags='PA')/Raw(load=tls_header + payload)
    p.time = BASE_TIME + i*0.1
    streams_b3.append(force_build(p))
add_test("B3_TLS_TRUNCATE", "L7: TLS Redaction/Truncation", streams_b3, 5, ["-t", "TCP.DstPort() == 443", "-T", "true"], check_type="TRUNCATION")

# C. Multi-Layer/Multi-Stream Tests
# =====================================================
# C1: Deep Encapsulation (Expected 10 saves: Inner TTL < 5)
streams_c1 = []
streams_c1.extend(create_tcp_stream(1, 10, "10.6.1", "8.8.8.8", BASE_TIME, encapsulation="GRE", special_inner_ttl=64))
streams_c1.extend(create_tcp_stream(11, 10, "10.6.1", "8.8.8.8", BASE_TIME, encapsulation="GRE", special_inner_ttl=1, anomaly="RST_END"))
add_test("C1_DEEP_TTL", "MultiLayer: Inner TTL Filter", streams_c1, 10, ["-t", "IP.TTL(2) < 5", "-p", "TCP.IsRst()"])


# C2: Directional/Buffer Stress (Expected 2 saves: client & server files for one stream)
streams_c2 = []
c_ip, s_ip = "10.7.7.1", "10.7.7.2"
for i in range(6):
    p = Ether()/IP(src=c_ip, dst=s_ip)/TCP(sport=50000, dport=80, seq=1000+i, flags='A')
    p.time = BASE_TIME+i
    streams_c2.append(force_build(p))
for i in range(50):
    p = Ether()/IP(src=s_ip, dst=c_ip)/TCP(sport=80, dport=50000, seq=5000+i, flags='A')
    p.time = BASE_TIME+5.1+(i*0.001)
    streams_c2.append(force_build(p))
p = Ether()/IP(src=c_ip, dst=s_ip)/TCP(sport=50000, dport=80, seq=2000, flags='PA', window=9999)
p.time = BASE_TIME+6.0
streams_c2.append(force_build(p))
add_test("C2_DIRECTIONAL", "Buffer: Directional Separation", streams_c2, 2, ["-t", "TCP.WindowSize() == 9999", "-M", "separate", "-b", "10"])

# --- WRITE MANIFEST ---
if __name__ == '__main__':
    with open(os.path.join(OUTPUT_DIR, MANIFEST_FILE), "w") as f:
        json.dump(TEST_MANIFEST, f, indent=4)

    logger.info(f"\nManifest written to {OUTPUT_DIR}/{MANIFEST_FILE}")
    logger.info(f"Total tests defined: {len(TEST_MANIFEST)}")
    logger.info("PCAP generation complete. Run run_validation.py next.")

