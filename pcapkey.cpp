/**
 * @file pcapkey.cpp
 * @author James Mathewson
 * @version 0.9.4 beta
 * @brief Implementation of the packet parser and key generator.
 */

#include "pcapkey.h"
#include <iomanip> // for string formatting
#include <sstream> // for string formatting
#include <arpa/inet.h> // For ntohs

// --- Protocol Defines ---
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4
#endif
#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif
#ifndef IPPROTO_ESP
#define IPPROTO_ESP 50
#endif
#ifndef IPPROTO_AH
#define IPPROTO_AH 51
#endif

// --- DLT Defines ---
#ifndef DLT_NULL
#define DLT_NULL 0
#endif
#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif
#ifndef DLT_RAW
#define DLT_RAW 12  // Default for Linux
#endif
#ifndef DLT_RAW_ALT
#define DLT_RAW_ALT 14 // BSD variant
#endif
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif
#ifndef DLT_IPV4
#define DLT_IPV4 228
#endif
#ifndef DLT_IPV6
#define DLT_IPV6 229
#endif

// Linux cooked header (SLL)
struct sll_header {
    uint16_t sll_pkttype;   // packet type
    uint16_t sll_hatype;    // link-layer address type
    uint16_t sll_halen;     // link-layer address length
    uint8_t  sll_addr[8];   // link-layer address
    uint16_t sll_protocol;  // protocol
};

namespace pcapabvparser {

/**
 * @brief Internal recursive helper for parse_packet.
 */
static void parse_recursive(
    uint32_t current_proto_type,
    const uint8_t* packet,
    size_t& offset,
    size_t caplen,
    std::vector<uint8_t>& key,
    bool& key_locked,
    PacketOffsets_t& offsets,
    ProtocolStack_t& stack,
    const std::set<uint16_t>& tls_ports)
{
    if (offset >= caplen) return;

    ProtocolInfo info;
    info.type = current_proto_type;
    info.data_ptr = packet + offset;
    
    uint32_t next_proto_type = 0;

    switch (current_proto_type) {
        // --- L3 Protocols ---
        case ETHERTYPE_IP: { // IPv4
            if (offset + sizeof(ip) > caplen) return;
            const ip* ipv4 = reinterpret_cast<const ip*>(packet + offset);
            if (ipv4->ip_v != 4) return;
            
            info.header_length = ipv4->ip_hl * 4;
            if (offset + info.header_length > caplen) return;
            info.payload_length = ntohs(ipv4->ip_len) - info.header_length;
            offset += info.header_length;

            if (!key_locked && key.empty()) {
                offsets.l3_offset = (size_t)(info.data_ptr - packet);
                offsets.ip_protocol = ipv4->ip_p;
                offsets.ethertype = ETHERTYPE_IP;

                key.push_back((uint8_t)((ETHERTYPE_IP >> 8) & 0xFF));
                key.push_back((uint8_t)(ETHERTYPE_IP & 0xFF));
                
                if (ntohl(ipv4->ip_src.s_addr) > ntohl(ipv4->ip_dst.s_addr)) {
                    key.insert(key.end(), (uint8_t*)&ipv4->ip_src, (uint8_t*)&ipv4->ip_src + 4);
                    key.insert(key.end(), (uint8_t*)&ipv4->ip_dst, (uint8_t*)&ipv4->ip_dst + 4);
                    offsets.originalAddrPortOrdering = true;
                } else {
                    key.insert(key.end(), (uint8_t*)&ipv4->ip_dst, (uint8_t*)&ipv4->ip_dst + 4);
                    key.insert(key.end(), (uint8_t*)&ipv4->ip_src, (uint8_t*)&ipv4->ip_src + 4);
                    offsets.originalAddrPortOrdering = false;
                }
            }
            next_proto_type = ipv4->ip_p;
            break;
        }

        case ETHERTYPE_IPV6: { // IPv6
            if (offset + sizeof(ip6_hdr) > caplen) return;
            const ip6_hdr* ipv6 = reinterpret_cast<const ip6_hdr*>(packet + offset);
            if ((ipv6->ip6_vfc & 0xF0) >> 4 != 6) return;
            
            info.header_length = sizeof(ip6_hdr);
            info.payload_length = ntohs(ipv6->ip6_plen);
            offset += info.header_length;
            
            if (!key_locked && key.empty()) {
                offsets.l3_offset = (size_t)(info.data_ptr - packet);
                offsets.ip_protocol = ipv6->ip6_nxt;
                offsets.ethertype = ETHERTYPE_IPV6;

                key.push_back((uint8_t)((ETHERTYPE_IPV6 >> 8) & 0xFF));
                key.push_back((uint8_t)(ETHERTYPE_IPV6 & 0xFF));

                if (memcmp(&ipv6->ip6_src, &ipv6->ip6_dst, 16) > 0) {
                    key.insert(key.end(), (uint8_t*)&ipv6->ip6_src, (uint8_t*)&ipv6->ip6_src + 16);
                    key.insert(key.end(), (uint8_t*)&ipv6->ip6_dst, (uint8_t*)&ipv6->ip6_dst + 16);
                    offsets.originalAddrPortOrdering = true;
                } else {
                    key.insert(key.end(), (uint8_t*)&ipv6->ip6_dst, (uint8_t*)&ipv6->ip6_dst + 16);
                    key.insert(key.end(), (uint8_t*)&ipv6->ip6_src, (uint8_t*)&ipv6->ip6_src + 16);
                    offsets.originalAddrPortOrdering = false;
                }
            }
            next_proto_type = ipv6->ip6_nxt;
            break;
        }
        
        case ETHERTYPE_ARP:
        case ETHERTYPE_REVARP:
            info.header_length = caplen - offset;
            offset = caplen;
            key_locked = true;
            break;
            
        // --- L4 Protocols ---
        case IPPROTO_TCP: {
            if (offset + sizeof(tcphdr) > caplen) return;
            const tcphdr* tcp = reinterpret_cast<const tcphdr*>(packet + offset);
            info.header_length = tcp->th_off * 4;
            if (offset + info.header_length > caplen) return;
            offset += info.header_length;
            info.payload_length = caplen - offset;

            if (!key_locked && !key.empty()) {
                offsets.l4_offset = (size_t)(info.data_ptr - packet);
                offsets.payload_offset = offset;
                offsets.src_port = ntohs(tcp->th_sport);
                offsets.dst_port = ntohs(tcp->th_dport);

                key.push_back(IPPROTO_TCP);
                uint16_t p1 = offsets.src_port, p2 = offsets.dst_port;
                if (!offsets.originalAddrPortOrdering) std::swap(p1, p2);
                key.push_back((uint8_t)((p1 >> 8) & 0xFF)); key.push_back((uint8_t)(p1 & 0xFF));
                key.push_back((uint8_t)((p2 >> 8) & 0xFF)); key.push_back((uint8_t)(p2 & 0xFF));
                
                key_locked = true;
            }

            if (info.payload_length > 0) {
                uint16_t sp = ntohs(tcp->th_sport);
                uint16_t dp = ntohs(tcp->th_dport);
                if (tls_ports.count(sp) || tls_ports.count(dp)) next_proto_type = PROTO_TLS;
                else if (sp == 53 || dp == 53) next_proto_type = PROTO_DNS;
            }
            break;
        }
            
        case IPPROTO_UDP: {
            if (offset + sizeof(udphdr) > caplen) return;
            const udphdr* udp = reinterpret_cast<const udphdr*>(packet + offset);
            info.header_length = sizeof(udphdr);
            info.payload_length = ntohs(udp->uh_ulen) - info.header_length;
            offset += info.header_length;
            
            if (!key_locked && !key.empty()) {
                offsets.l4_offset = (size_t)(info.data_ptr - packet);
                offsets.payload_offset = offset;
                offsets.src_port = ntohs(udp->uh_sport);
                offsets.dst_port = ntohs(udp->uh_dport);

                key.push_back(IPPROTO_UDP);
                uint16_t p1 = offsets.src_port, p2 = offsets.dst_port;
                if (!offsets.originalAddrPortOrdering) std::swap(p1, p2);
                key.push_back((uint8_t)((p1 >> 8) & 0xFF)); key.push_back((uint8_t)(p1 & 0xFF));
                key.push_back((uint8_t)((p2 >> 8) & 0xFF)); key.push_back((uint8_t)(p2 & 0xFF));
                
                key_locked = true;
            }
            
            if (info.payload_length > 0) {
                uint16_t sp = ntohs(udp->uh_sport);
                uint16_t dp = ntohs(udp->uh_dport);
                if (sp == 53 || dp == 53) next_proto_type = PROTO_DNS;
            }
            break;
        }

        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6: {
             info.header_length = (current_proto_type == IPPROTO_ICMP) ? 8 : 4;
             if (offset + info.header_length > caplen) return;
             
             if (!key_locked && !key.empty()) {
                 offsets.l4_offset = (size_t)(info.data_ptr - packet);
                 if (current_proto_type == IPPROTO_ICMP) {
                    const icmp* ic = reinterpret_cast<const icmp*>(info.data_ptr);
                    offsets.icmp_type = ic->icmp_type; 
                    offsets.icmp_code = ic->icmp_code;
                    key.push_back(ic->icmp_type);
                    key.push_back(ic->icmp_code);
                 } else {
                    const icmp6_hdr* ic6 = reinterpret_cast<const icmp6_hdr*>(info.data_ptr);
                    offsets.icmp_type = ic6->icmp6_type; 
                    offsets.icmp_code = ic6->icmp6_code;
                    key.push_back(ic6->icmp6_type);
                    key.push_back(ic6->icmp6_code);
                 }
                 key.push_back((uint8_t)current_proto_type);
                 key_locked = true;
             }
             offset += info.header_length;
             break;
        }

        case IPPROTO_GRE: {
            if (offset + sizeof(gre_hdr) > caplen) return;
            const gre_hdr* gre = reinterpret_cast<const gre_hdr*>(packet + offset);
            info.header_length = sizeof(gre_hdr);
            uint16_t flags = ntohs(gre->flags_and_version);
            if (flags & 0x8000) info.header_length += 4; // Checksum/Offset
            if (flags & 0x2000) info.header_length += 4; // Key
            if (flags & 0x1000) info.header_length += 4; // Sequence

            if (offset + info.header_length > caplen) return;

            if (!key_locked && !key.empty()) {
                key.push_back(IPPROTO_GRE);
                key_locked = true; 
            }
            
            offset += info.header_length;
            next_proto_type = ntohs(gre->protocol_type);
            break;
        }
            
        case IPPROTO_IPIP:
        case IPPROTO_IPV6:
            info.header_length = 0;
             if (!key_locked && !key.empty()) {
                key.push_back((uint8_t)current_proto_type);
                key_locked = true;
            }
            next_proto_type = (current_proto_type == IPPROTO_IPIP) ? ETHERTYPE_IP : ETHERTYPE_IPV6;
            break;
            
        case IPPROTO_ESP:
        case IPPROTO_AH:
            info.header_length = 8; 
             if (!key_locked && !key.empty()) {
                key.push_back((uint8_t)current_proto_type);
                key_locked = true;
            }
            offset = caplen; 
            break;

        case PROTO_DNS:
        case PROTO_TLS:
            info.header_length = 0;
            info.payload_length = caplen - offset;
            offset = caplen;
            break;

        default:
            offset = caplen;
            break;
    }

    stack.push_back(info);
    
    if (next_proto_type != 0 && offset < caplen) {
        parse_recursive(next_proto_type, packet, offset, caplen,
                        key, key_locked, offsets, stack, tls_ports);
    }
}

/**
 * @brief Entry point for packet parsing. Handles L2, then recurses for L3+.
 */
std::tuple<std::unique_ptr<std::vector<uint8_t>>,
           std::unique_ptr<PacketOffsets_t>,
           std::unique_ptr<ProtocolStack_t>>
parse_packet(
    int l2_proto,
    const uint8_t* packet,
    size_t caplen,
    const std::set<uint16_t>& tls_ports)
{
    auto key = std::make_unique<std::vector<uint8_t>>();
    auto offsets = std::make_unique<PacketOffsets_t>();
    auto stack = std::make_unique<ProtocolStack_t>();

    size_t offset = 0;
    bool key_locked = false;
    
    key->reserve(40);

    uint32_t next_proto_type = 0;

    // --- Layer 2 Parsing ---
    switch (l2_proto) {
        case DLT_EN10MB: { // Ethernet (1)
            if (offset + sizeof(ether_header) <= caplen) {
                ProtocolInfo l2_info{DLT_EN10MB, packet, sizeof(ether_header), 0};
                const ether_header* eth = reinterpret_cast<const ether_header*>(packet);
                next_proto_type = ntohs(eth->ether_type);
                offsets->ethertype = next_proto_type;
                stack->push_back(l2_info);
                offset += sizeof(ether_header);
            }
            break;
        }
        // --- FIX: Handle Linux Cooked Capture (SLL) ---
        case DLT_LINUX_SLL: { // (113)
             if (offset + sizeof(sll_header) <= caplen) {
                 ProtocolInfo l2_info{DLT_LINUX_SLL, packet, sizeof(sll_header), 0};
                 const sll_header* sll = reinterpret_cast<const sll_header*>(packet);
                 next_proto_type = ntohs(sll->sll_protocol);
                 // SLL doesn't exactly have an EtherType in the same way, but we use it for L3 type
                 offsets->ethertype = next_proto_type;
                 stack->push_back(l2_info);
                 offset += sizeof(sll_header);
             }
             break;
        }
        // --- FIX: Handle Raw IP (various DLTs) ---
        case DLT_NULL: { // Loopback (0)
            if (offset + 4 <= caplen) {
                 // Skip 4-byte protocol family header
                 offset += 4;
                 // Fallthrough to RAW logic
                 if (offset < caplen) {
                     uint8_t ver = (packet[offset] >> 4);
                     if (ver == 4) next_proto_type = ETHERTYPE_IP;
                     else if (ver == 6) next_proto_type = ETHERTYPE_IPV6;
                 }
            }
            break;
        }
        case DLT_RAW:     // (12)
        case DLT_RAW_ALT: // (14)
        case DLT_IPV4:    // (228)
        case DLT_IPV6:    // (229)
        {
             // No L2 header, starts immediately with IP
             if (l2_proto == DLT_IPV4) next_proto_type = ETHERTYPE_IP;
             else if (l2_proto == DLT_IPV6) next_proto_type = ETHERTYPE_IPV6;
             else if (caplen >= 1) { // DLT_RAW, guess from nibble
                 uint8_t ver = (packet[0] >> 4);
                 if (ver == 4) next_proto_type = ETHERTYPE_IP;
                 else if (ver == 6) next_proto_type = ETHERTYPE_IPV6;
             }
             break;
        }

        default:
            // Unsupported L2
            break; 
    }

    // --- Start recursion at L3 ---
    if (next_proto_type != 0) {
        parse_recursive(next_proto_type, packet, offset, caplen,
                        *key, key_locked, *offsets, *stack, tls_ports);
    }

    if (key->empty()) {
        key->clear();
    }
    
    return std::make_tuple(std::move(key), std::move(offsets), std::move(stack));
}

// ... (print_simplekey and print_key_debug are unchanged) ...
std::string print_simplekey(const std::vector<uint8_t>& key) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (const auto& byte : key) oss << std::setw(2) << static_cast<int>(byte);
    return oss.str();
}
// (print_key_debug same as before)

} //end namespace
