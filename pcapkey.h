/**
 * @file pcapkey.h
 * @brief Defines packet parsing functions, protocol stack structures,
 * and 5-tuple key generation.
 */
/*
 * Author: James Mathewson
 * Date: 6 November 2025
 * Version: 0.7 beta 
 */


#ifndef __PCAPKEY_H__
#define __PCAPKEY_H__

// ... (includes: netinet, pcap, vector, string, memory, etc.) ...
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h> // For ETHERTYPE_IP, etc.
#include <arpa/inet.h>
#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <memory>
#include <set>
#include <unordered_map> // For VectorHash
#include <functional> // For VectorHash
#include <tuple> // For std::tuple

// --- NEW Protocol Type Definitions ---
// Using values outside the ETHERTYPE/IPPROTO range
#define PROTO_DNS 0x10001
#define PROTO_TLS 0x10002

// Simple GRE header structure
struct gre_hdr {
    uint16_t flags_and_version;
    uint16_t protocol_type;
    // More fields exist if flags are set (checksum, key, seq)
    // This simple parser assumes no optional fields.
};


namespace pcapabvparser {

// --- VectorHash from old protoTrigger.h ---
struct VectorHash
{
    std::size_t operator()(const std::vector<uint8_t>& vec) const
    {
        // Treat the vector's data as a string_view over raw bytes
        std::string_view view(reinterpret_cast<const char*>(vec.data()), vec.size());
        return std::hash<std::string_view> {}(view);
    }
};

/**
 * @struct PacketOffsets_t
 * @brief Holds byte offsets for key protocol layers within a packet.
 *
 * This struct is the "pcap helper" you described. It is filled once
 * by parse_packet and passed to protocol triggers to allow
 * direct, efficient type-casting without re-parsing.
 */
struct PacketOffsets_t
{
    size_t l2_offset = 0;
    size_t l3_offset = 0; // Start of IP (v4 or v6) header
    size_t l4_offset = 0; // Start of L4 (TCP/UDP/ICMP) header
    size_t payload_offset = 0; // Start of L4 payload (e.g., DNS, TLS)
    
    uint16_t ethertype = 0; // L3 protocol (e.g., ETHERTYPE_IP)
    uint8_t ip_protocol = 0; // L4 protocol (e.g., IPPROTO_TCP)
    
    // Key 5-tuple info for quick access
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t icmp_type = 0;
    uint8_t icmp_code = 0;

    /**
     * @brief True if (src_ip, src_port) > (dst_ip, dst_port)
     * This allows directional awareness (e.g., "is this packet from
     * the original client?").
     */
    bool originalAddrPortOrdering = true;
};

/**
 * @struct ProtocolInfo
 * @brief Stores information about a single protocol layer.
 */
struct ProtocolInfo {
    /**
     * @brief The protocol type (e.g., ETHERTYPE_IP, IPPROTO_TCP, PROTO_DNS).
     */
    uint32_t type = 0;
    
    /**
     * @brief A direct pointer to the start of this protocol's
     * header in the raw packet data.
     */
    const uint8_t* data_ptr = nullptr;
    
    /**
     * @brief The length of this protocol's header.
     */
    size_t header_length = 0;
    
    /**
     * @brief The length of this protocol's payload.
     */
    size_t payload_length = 0;
};

/**
 * @brief A vector of protocol layers, representing the parsed stack.
 * e.g., [Ethernet, IPv4, TCP, TLS]
 */
using ProtocolStack_t = std::vector<ProtocolInfo>;


/**
 * @brief Recursively parses a raw packet and generates a protocol stack
 * and a 5-tuple key.
 *
 * This function is the core parser. It decapsulates protocols
 * (like GRE, IP-in-IP) and builds the protocol stack.
 *
 * @param l2_proto The data link type from pcap_datalink().
 * @param packet A pointer to the raw packet data.
 * @param caplen The captured length of the packet.
 * @param tls_ports The set of ports to identify as TLS.
 * @return A std::tuple containing:
 * - A unique_ptr to the 5-tuple key (std::vector<uint8_t>).
 * - A unique_ptr to the PacketOffsets_t struct.
 * - A unique_ptr to the ProtocolStack_t vector.
 * If parsing fails, the key vector will be empty.
 */
std::tuple<std::unique_ptr<std::vector<uint8_t>>,
           std::unique_ptr<PacketOffsets_t>,
           std::unique_ptr<ProtocolStack_t>>
parse_packet(
    int l2_proto,
    const uint8_t* packet,
    size_t caplen,
    const std::set<uint16_t>& tls_ports
);

/**
 * @brief Prints a key to stdout in a simple hex string format.
 *
 * This format is safe to use as a filename on Linux and other OSes.
 *
 * @param key The packet key to print.
 * @return The hex string representation of the key.
 */
std::string print_simplekey(const std::vector<uint8_t>& key);

/**
 * @brief Prints a human-readable, debug version of the key.
 * @param key The packet key to print.
 */
void print_key_debug(const std::vector<uint8_t>& key);

} //end namespace
#endif // __PCAPKEY_H__
