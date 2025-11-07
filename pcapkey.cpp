/**
 * @file pcapkey.cpp
 * @brief Implementation of the packet parser and key generator.
 */

#include "pcapkey.h"
#include <iomanip> // for string formatting
#include <sstream> // for string formatting

// Define IPPROTO_IPIP
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4
#endif
// Define IPPROTO_GRE
#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif


namespace pcapabvparser {

/**
 * @brief Internal recursive helper for parse_packet.
 * @param current_proto_type The protocol type to parse (e.g., ETHERTYPE_IP).
 * @param packet Pointer to the start of the *full* packet.
 * @param offset The *current offset* into the packet where we are parsing.
 * @param caplen The *total* captured length of the packet.
 * @param key The 5-tuple key being built.
 * @param offsets The PacketOffsets_t helper being built.
 * @param stack The ProtocolStack_t being built.
 * @param tls_ports The set of ports to identify as TLS.
 */
static void parse_recursive(
    uint32_t current_proto_type,
    const uint8_t* packet,
    size_t& offset,
    size_t caplen,
    std::vector<uint8_t>& key,
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
        // --- L3 Protocols (EtherTypes) ---
        case ETHERTYPE_IP: { // IPv4
            if (offset + sizeof(ip) > caplen) return;
            const ip* ipv4 = reinterpret_cast<const ip*>(packet + offset);
            
            if (ipv4->ip_v != 4) return; // Not IPv4
            
            info.header_length = ipv4->ip_hl * 4;
            if (offset + info.header_length > caplen) return; // Bad header len
            
            info.payload_length = ntohs(ipv4->ip_len) - info.header_length;
            offset += info.header_length;

            offsets.l3_offset = (size_t)(info.data_ptr - packet);
            offsets.ip_protocol = ipv4->ip_p;
            
            // --- Key Generation (IPv4) ---
            if (key.empty()) { // Only key on the *first* L3 header
                key.push_back((uint8_t)((offsets.ethertype >> 8) & 0xFF));
                key.push_back((uint8_t)(offsets.ethertype & 0xFF));
                
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
            // --- End Key Gen ---

            next_proto_type = ipv4->ip_p;
            break;
        }

        case ETHERTYPE_IPV6: { // IPv6
            if (offset + sizeof(ip6_hdr) > caplen) return;
            const ip6_hdr* ipv6 = reinterpret_cast<const ip6_hdr*>(packet + offset);

            if ((ipv6->ip6_vfc & 0xF0) >> 4 != 6) return; // Not IPv6
            
            info.header_length = sizeof(ip6_hdr);
            info.payload_length = ntohs(ipv6->ip6_plen);
            offset += info.header_length;
            
            offsets.l3_offset = (size_t)(info.data_ptr - packet);
            offsets.ip_protocol = ipv6->ip6_nxt;
            
            // TODO: Handle IPv6 Extension Headers
            
            // --- Key Generation (IPv6) ---
            if (key.empty()) {
                key.push_back((uint8_t)((offsets.ethertype >> 8) & 0xFF));
                key.push_back((uint8_t)(offsets.ethertype & 0xFF));

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
            // --- End Key Gen ---
            
            next_proto_type = ipv6->ip6_nxt;
            break;
        }
        
        case ETHERTYPE_ARP:
        case ETHERTYPE_REVARP:
            // No L4, parsing stops
            info.header_length = caplen - offset; // Consume rest of packet
            offset = caplen;
            break;
            
        // --- L4 Protocols (IPProtos) ---
        case IPPROTO_TCP: { // TCP
            if (offset + sizeof(tcphdr) > caplen) return;
            const tcphdr* tcp = reinterpret_cast<const tcphdr*>(packet + offset);

            info.header_length = tcp->th_off * 4;
            if (offset + info.header_length > caplen) return; // Bad header len
            
            offset += info.header_length;
            info.payload_length = caplen - offset; // Assume rest of packet
            
            offsets.l4_offset = (size_t)(info.data_ptr - packet);
            offsets.payload_offset = offset;
            offsets.src_port = ntohs(tcp->th_sport);
            offsets.dst_port = ntohs(tcp->th_dport);

            // --- Key Generation (L4) ---
            if (key.size() > 2) { // L3 key was added
                key.push_back(IPPROTO_TCP);
                
                uint16_t p1 = offsets.src_port, p2 = offsets.dst_port;
                if (!offsets.originalAddrPortOrdering) {
                    std::swap(p1, p2); // Use normalized port order
                }
                
                key.push_back((uint8_t)((p1 >> 8) & 0xFF));
                key.push_back((uint8_t)(p1 & 0xFF));
                key.push_back((uint8_t)((p2 >> 8) & 0xFF));
                key.push_back((uint8_t)(p2 & 0xFF));
            }
            // --- End Key Gen ---

            // Check for L7
            if (info.payload_length > 0) {
                if (tls_ports.count(offsets.src_port) || tls_ports.count(offsets.dst_port)) {
                    next_proto_type = PROTO_TLS;
                } else if (offsets.src_port == 53 || offsets.dst_port == 53) {
                    next_proto_type = PROTO_DNS;
                }
            }
            break;
        }
            
        case IPPROTO_UDP: { // UDP
            if (offset + sizeof(udphdr) > caplen) return;
            const udphdr* udp = reinterpret_cast<const udphdr*>(packet + offset);

            info.header_length = sizeof(udphdr);
            // --- FIX: Use uh_ulen for Linux, not uh_len ---
            info.payload_length = ntohs(udp->uh_ulen) - info.header_length;
            offset += info.header_length;
            
            offsets.l4_offset = (size_t)(info.data_ptr - packet);
            offsets.payload_offset = offset;
            offsets.src_port = ntohs(udp->uh_sport);
            offsets.dst_port = ntohs(udp->uh_dport);
            
            // --- Key Generation (L4) ---
            if (key.size() > 2) { // L3 key was added
                key.push_back(IPPROTO_UDP);
                
                uint16_t p1 = offsets.src_port, p2 = offsets.dst_port;
                if (!offsets.originalAddrPortOrdering) {
                    std::swap(p1, p2); // Use normalized port order
                }
                
                key.push_back((uint8_t)((p1 >> 8) & 0xFF));
                key.push_back((uint8_t)(p1 & 0xFF));
                key.push_back((uint8_t)((p2 >> 8) & 0xFF));
                key.push_back((uint8_t)(p2 & 0xFF));
            }
            // --- End Key Gen ---
            
            // Check for L7
            if (info.payload_length > 0) {
                if (offsets.src_port == 53 || offsets.dst_port == 53) {
                    next_proto_type = PROTO_DNS;
                }
            }
            break;
        }

        case IPPROTO_ICMP: { // ICMPv4
            if (offset + sizeof(icmp) > caplen) return;
            const icmp* icmpv4 = reinterpret_cast<const icmp*>(packet + offset);
            
            info.header_length = 8; // Type, Code, Cksum, Rest of Header
            offset += info.header_length;
            
            offsets.l4_offset = (size_t)(info.data_ptr - packet);
            offsets.icmp_type = icmpv4->icmp_type;
            offsets.icmp_code = icmpv4->icmp_code;
            
            // --- Key Generation (L4) ---
            if (key.size() > 2) {
                key.push_back(IPPROTO_ICMP);
                // (Ports are 0, which is fine)
            }
            // --- End Key Gen ---
            break; // Stop parsing
        }

        case IPPROTO_ICMPV6: { // ICMPv6
            if (offset + sizeof(icmp6_hdr) > caplen) return;
            const icmp6_hdr* icmpv6 = reinterpret_cast<const icmp6_hdr*>(packet + offset);
            
            info.header_length = 4; // Type, Code, Cksum
            offset += info.header_length;
            
            offsets.l4_offset = (size_t)(info.data_ptr - packet);
            offsets.icmp_type = icmpv6->icmp6_type;
            offsets.icmp_code = icmpv6->icmp6_code;
            
            // --- Key Generation (L4) ---
            if (key.size() > 2) {
                key.push_back(IPPROTO_ICMPV6);
                // (Ports are 0, which is fine)
            }
            // --- End Key Gen ---
            break; // Stop parsing
        }
            
        case IPPROTO_GRE: { // GRE
            if (offset + sizeof(gre_hdr) > caplen) return;
            const gre_hdr* gre = reinterpret_cast<const gre_hdr*>(packet + offset);
            
            // This is a minimal parser assuming no optional fields
            info.header_length = 4;
            offset += info.header_length;
            
            next_proto_type = ntohs(gre->protocol_type);
            break; // Recurse
        }
            
        case IPPROTO_IPIP: { // IP-in-IP
            // No header to parse, the payload *is* the next IP header
            info.header_length = 0;
            next_proto_type = ETHERTYPE_IP; // Decapsulate
            break; // Recurse
        }
            
        case PROTO_DNS:
        case PROTO_TLS: {
            // L7 protocols: just tag them, don't parse them here
            info.header_length = 0; // Header is part of L4 payload
            info.payload_length = caplen - offset;
            offset = caplen;
            break; // Stop
        }

        default: // Unknown protocol
            offset = caplen; // Stop parsing
            break;
    }

    stack.push_back(info);
    if (next_proto_type != 0 && offset < caplen) {
        parse_recursive(next_proto_type, packet, offset, caplen,
                        key, offsets, stack, tls_ports);
    }
}


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
    
    // Reserve space for a common key
    key->reserve(38); // Max for IPv6+TCP

    // --- FIX: Start parsing at L2 ---
    // The recursive function will handle L3 and above
    uint32_t next_proto_type = 0;
    
    // --- FIX: The switch now only handles L2 (DLT_) types ---
    switch (l2_proto) {
        case DLT_EN10MB: { // Ethernet
            ProtocolInfo l2_info;
            l2_info.type = DLT_EN10MB;
            l2_info.data_ptr = packet;
            
            if (offset + sizeof(ether_header) > caplen) {
                key->clear();
                return std::make_tuple(std::move(key), std::move(offsets), std::move(stack));
            }
            const ether_header* eth = reinterpret_cast<const ether_header*>(packet + offset);
            
            l2_info.header_length = sizeof(ether_header);
            offset += l2_info.header_length;
            
            next_proto_type = ntohs(eth->ether_type);
            // --- FIX: Use -> operator for unique_ptr ---
            offsets->ethertype = next_proto_type;
            offsets->l2_offset = 0;
            
            stack->push_back(l2_info);
            break;
        }
        
        // Add other L2 types here if needed (e.g., DLT_NULL, DLT_LINUX_SLL)
        
        default:
            // Unsupported L2
            key->clear(); 
            return std::make_tuple(std::move(key), std::move(offsets), std::move(stack));
    }
    
    // --- Start recursion at L3 ---
    if (next_proto_type != 0 && offset < caplen) {
        parse_recursive(next_proto_type, packet, offset, caplen,
                        *key, *offsets, *stack, tls_ports);
    }
    // ---

    if (key->empty()) {
        // Parsing failed to generate a key
        key->clear();
    }
    
    return std::make_tuple(std::move(key), std::move(offsets), std::move(stack));
}

// ... (print_simplekey and print_key_debug are unchanged) ...

std::string print_simplekey(const std::vector<uint8_t>& key) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (const auto& byte : key) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

void print_key_debug(const std::vector<uint8_t>& key) {
    if (key.empty()) {
        std::cout << "PRINTKEY: [EMPTY/INVALID]" << std::endl;
        return;
    }
    
    std::cout << "PRINTKEY: ########" << std::endl;
    std::cout << "  Raw: " << print_simplekey(key) << std::endl;
    
    uint16_t l3_proto = (key[0] << 8) | key[1];
    std::cout << "  L3 Proto: 0x" << std::hex << l3_proto << std::dec << std::endl;

    if (l3_proto == ETHERTYPE_IP) {
        std::cout << "  IPv4 Addr1: " << (int)key[2] << "." << (int)key[3] << "." << (int)key[4] << "." << (int)key[5] << std::endl;
        std::cout << "  IPv4 Addr2: " << (int)key[6] << "." << (int)key[7] << "." << (int)key[8] << "." << (int)key[9] << std::endl;
        
        if (key.size() > 10) { // Check if L4 key exists
            uint8_t l4_proto = key[10];
            std::cout << "  L4 Proto: " << (int)l4_proto << std::endl;
            
            if (l4_proto == IPPROTO_TCP || l4_proto == IPPROTO_UDP) {
                uint16_t port1 = (key[11] << 8) | key[12];
                uint16_t port2 = (key[13] << 8) | key[14];
                std::cout << "  Port1: " << port1 << std::endl;
                std::cout << "  Port2: " << port2 << std::endl;
            } else if (l4_proto == IPPROTO_ICMP) {
                std::cout << "  (ICMP, no ports)" << std::endl;
            }
        }
    } else if (l3_proto == ETHERTYPE_IPV6) {
        // ... (add IPv6 debug print) ...
    }
    std::cout << "END PRINTKEY #####\n" << std::endl;
}

} //end namespace