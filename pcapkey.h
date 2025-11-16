/**
 * @file pcapkey.h
 * @brief Defines packet parsing and Selectable Hashing Strategy.
 */

#ifndef __PCAPKEY_H__
#define __PCAPKEY_H__

#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <memory>
#include <set>
#include <unordered_map>
#include <functional>
#include <tuple>
#include <string_view>

#define PROTO_DNS 0x10001
#define PROTO_TLS 0x10002
#define PROTO_SMB 0x10003
#define PROTO_NFS 0x10004

namespace pcapabvparser {

struct PacketOffsets_t {
    size_t l2_offset = 0;
    size_t l3_offset = 0;
    size_t l4_offset = 0;
    size_t payload_offset = 0;
    uint16_t ethertype = 0;
    uint8_t ip_protocol = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t icmp_type = 0;
    uint8_t icmp_code = 0;
    bool originalAddrPortOrdering = true;
};

struct ProtocolInfo {
    uint32_t type = 0;
    const uint8_t* data_ptr = nullptr;
    size_t header_length = 0;
    size_t payload_length = 0;
};

using ProtocolStack_t = std::vector<ProtocolInfo>;

// =============================================================
// HASHING STRATEGY SELECTION
// =============================================================

// 1. Standard (Fastest, non-deterministic)
struct VectorHash {
    std::size_t operator()(const std::vector<uint8_t>& vec) const {
        std::string_view view(reinterpret_cast<const char*>(vec.data()), vec.size());
        return std::hash<std::string_view>{}(view);
    }
};

// 2. Bernstein (djb2) - Fast & Simple
struct BernsteinHash {
    std::size_t operator()(const std::vector<uint8_t>& vec) const {
        size_t hash = 5381;
        for (uint8_t byte : vec) {
            hash = ((hash << 5) + hash) + byte; /* hash * 33 + c */
        }
        return hash;
    }
};

// 3. FNV-1a - Deterministic & Robust (Default)
struct DeterministicHash {
    std::size_t operator()(const std::vector<uint8_t>& vec) const {
        size_t hash = 14695981039346656037ULL;
        for (uint8_t byte : vec) {
            hash ^= byte;
            hash *= 1099511628211ULL;
        }
        return hash;
    }
};

// Compile-time Selection Logic
#if defined(USE_STD_HASH)
    using hashFn = VectorHash;
#elif defined(USE_BERNSTEIN_HASH)
    using hashFn = BernsteinHash;
#else
    // Default: Ensure consistent multi-threaded behavior
    using hashFn = DeterministicHash;
#endif

// =============================================================

std::tuple<std::unique_ptr<std::vector<uint8_t>>,
           std::unique_ptr<PacketOffsets_t>,
           std::unique_ptr<ProtocolStack_t>>
parse_packet(
    int l2_proto,
    const uint8_t* packet,
    size_t caplen,
    const std::set<uint16_t>& tls_ports,
    const std::set<uint16_t>& dns_ports
);

std::string print_simplekey(const std::vector<uint8_t>& key);
void print_key_debug(const std::vector<uint8_t>& key);

}
#endif // __PCAPKEY_H__
