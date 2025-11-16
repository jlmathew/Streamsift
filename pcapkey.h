/**
 * @file pcapkey.h
 * @author James Mathewson
 * @version 1.0.0 alpha
 * @brief Defines packet parsing functions, protocol stack structures, and 5-tuple key generation.
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

// --- L7 Protocol Type Definitions ---
#define PROTO_DNS 0x10001
#define PROTO_TLS 0x10002
#define PROTO_SMB 0x10003 // <-- NEW
#define PROTO_NFS 0x10004 // <-- NEW

namespace pcapabvparser {

struct VectorHash {
    std::size_t operator()(const std::vector<uint8_t>& vec) const {
        std::string_view view(reinterpret_cast<const char*>(vec.data()), vec.size());
        return std::hash<std::string_view>{}(view);
    }
};

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

// --- UPDATED SIGNATURE ---
std::tuple<std::unique_ptr<std::vector<uint8_t>>,
           std::unique_ptr<PacketOffsets_t>,
           std::unique_ptr<ProtocolStack_t>>
parse_packet(
    int l2_proto,
    const uint8_t* packet,
    size_t caplen,
    const std::set<uint16_t>& tls_ports,
    const std::set<uint16_t>& dns_ports // <-- NEW ARGUMENT
);

std::string print_simplekey(const std::vector<uint8_t>& key);
void print_key_debug(const std::vector<uint8_t>& key);

} //end namespace
#endif // __PCAPKEY_H__
