/**
 * @file ProtoTrigger.cpp
 * @author James Mathewson
 * @version 0.9.19 beta
 * @brief Implementation of the protocol-specific trigger functions.
 */

#include "ProtoTrigger.h"
#include "pcapparser.h" // For Func
#include "Logger.h"
#include "pcapkey.h" // For protocol type defines

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h> // For udphdr
#include <iostream>     // Needed for debug string building

// --- DEBUG MACRO ---
// Uncomment the next line to enable verbose protocol stack logging
#define DEBUG_PROTO

#ifdef DEBUG_PROTO
    #define LOG_PROTO(msg) Logger::log("[DEBUG][PROTO] " + std::string(msg))
#else
    #define LOG_PROTO(msg) do {} while(0)
#endif

namespace pcapabvparser {

// --- Helper function for indexed access ---

/**
 * @brief Finds the Nth instance of a protocol in the stack.
 * @param stack The protocol stack.
 * @param proto_type The protocol type to find (e.g., ETHERTYPE_IP).
 * @param index The 1-based index of the instance to find. 0 means "first available".
 * @return A pointer to the ProtocolInfo, or nullptr if not found.
 */
const ProtocolInfo* findNthProtocol(const ProtocolStack_t* stack, uint32_t proto_type, int index) {
    if (!stack) return nullptr;
    int count = 0;
    for (const auto& info : *stack) {
        if (info.type == proto_type) {
            count++;
            // --- FIX: Handle index == 0 as "first match" ---
            if (index <= 0 || count == index) {
                #ifdef DEBUG_PROTO
                LOG_PROTO("Found proto " + std::to_string(proto_type) + " at index " + std::to_string(count) + " (requested " + std::to_string(index) + ")");
                #endif
                return &info;
            }
        }
    }
    #ifdef DEBUG_PROTO
    if (index > 0) {
        LOG_PROTO("Failed to find proto " + std::to_string(proto_type) + " at index " + std::to_string(index) + ". Total found: " + std::to_string(count));
    }
    #endif
    return nullptr;
}


// --- protoTcpTrigger ---
void protoTcpTrigger::createNameLambda() {
    // Capture a weak_ptr to self to avoid cycles/crashes
    std::weak_ptr<protoTcpTrigger> self = shared_from_this();

    // Helper macro to safely get the TCP header
    #define GET_TCP_HDR_BY_INDEX(spt, index, hdr_ptr) \
        const ProtocolInfo* info = findNthProtocol(spt->m_protoStack, IPPROTO_TCP, index); \
        if (!info || !info->data_ptr) return 0; \
        const tcphdr* hdr_ptr = reinterpret_cast<const tcphdr*>(info->data_ptr);

    // Helper macro for "Check ALL instances" boolean logic
    #define CHECK_ALL_TCP(spt, check_name, check_expr) \
        if (!spt->m_protoStack) return 0; \
        int found_tcp = 0; \
        for (const auto& info : *spt->m_protoStack) { \
            if (info.type == IPPROTO_TCP) { \
                found_tcp++; \
                const tcphdr* tcp = reinterpret_cast<const tcphdr*>(info.data_ptr); \
                if (check_expr) { \
                    /* LOG_PROTO(std::string(check_name) + " matched on TCP instance " + std::to_string(found_tcp)); */ \
                    return 1; \
                } \
            } \
        } \
        return 0;

    /**
     * @brief Returns 1 if the TCP SYN flag is set, 0 otherwise.
     * @param index (optional) 0=all, 1=first, 2=second, etc.
     */
    m_protoMap["TCP.IsSyn"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            if (args.empty() || args[0] == 0) {
                CHECK_ALL_TCP(spt, "TCP.IsSyn(0)", tcp->th_flags & TH_SYN);
            } else {
                GET_TCP_HDR_BY_INDEX(spt, args[0], tcp);
                return (int)(tcp->th_flags & TH_SYN);
            }
        } return 0;
    };
   
    /**
     * @brief Returns 1 if the TCP RST flag is set, 0 otherwise.
     * @param index (optional) 0=all, 1=first, 2=second, etc.
     */
    m_protoMap["TCP.IsRst"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            if (args.empty() || args[0] == 0) {
                CHECK_ALL_TCP(spt, "TCP.IsRst(0)", tcp->th_flags & TH_RST);
            } else {
                GET_TCP_HDR_BY_INDEX(spt, args[0], tcp);
                return (int)(tcp->th_flags & TH_RST);
            }
        } return 0;
    };
   
    /**
     * @brief Returns 1 if the TCP FIN flag is set, 0 otherwise.
     * @param index (optional) 0=all, 1=first, 2=second, etc.
     */
    m_protoMap["TCP.IsFin"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            if (args.empty() || args[0] == 0) {
                CHECK_ALL_TCP(spt, "TCP.IsFin(0)", tcp->th_flags & TH_FIN);
            } else {
                GET_TCP_HDR_BY_INDEX(spt, args[0], tcp);
                return (int)(tcp->th_flags & TH_FIN);
            }
        } return 0;
    };
   
    /**
     * @brief Returns 1 if the TCP ACK flag is set, 0 otherwise.
     * @param index (optional) 0=all, 1=first, 2=second, etc.
     */
    m_protoMap["TCP.IsAck"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            if (args.empty() || args[0] == 0) {
                CHECK_ALL_TCP(spt, "TCP.IsAck(0)", tcp->th_flags & TH_ACK);
            } else {
                GET_TCP_HDR_BY_INDEX(spt, args[0], tcp);
                return (int)(tcp->th_flags & TH_ACK);
            }
        } return 0;
    };

    /**
     * @brief Returns 1 if TCP flags are set to an illegal combination (e.g., SYN+RST).
     * @param index (optional) 0=all, 1=first, 2=second, etc.
     */
    m_protoMap["TCP.IsIllegal"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            if (args.empty() || args[0] == 0) {
                CHECK_ALL_TCP(spt, "TCP.IsIllegal(0)", (tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_RST));
            } else {
                GET_TCP_HDR_BY_INDEX(spt, args[0], tcp);
                return (int)((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_RST));
            }
        } return 0;
    };
   
    /**
     * @brief Returns the TCP Window Size value.
     * @param index (optional) 0=all (returns first found), 1=first, 2=second, etc.
     */
    m_protoMap["TCP.WindowSize"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            int index = (args.empty() || args[0] == 0) ? 1 : args[0];
            GET_TCP_HDR_BY_INDEX(spt, index, tcp);
            return (int)ntohs(tcp->th_win);
        } return 0;
    };

    m_protoMap["TCP.SrcPort"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            int index = (args.empty() || args[0] == 0) ? 1 : args[0];
            GET_TCP_HDR_BY_INDEX(spt, index, tcp);
            return (int)ntohs(tcp->th_sport);
        } return 0;
    };
   
    m_protoMap["TCP.DstPort"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            int index = (args.empty() || args[0] == 0) ? 1 : args[0];
            GET_TCP_HDR_BY_INDEX(spt, index, tcp);
            return (int)ntohs(tcp->th_dport);
        } return 0;
    };

    /**
     * @brief Returns 1 if the packet is from the original client (initiator of the 5-tuple), 0 otherwise.
     * This check is based on the *key-defining* layer, not encapsulation.
     */
    m_protoMap["TCP.IsClientPacket"] = [self](const std::vector<int>&) {
        if (auto spt = self.lock()) {
            if (!spt->m_packetLayerHelper) return 0;
            // 'true' means client->server (original) direction
            return (int)(spt->m_packetLayerHelper->originalAddrPortOrdering);
        } return 0;
    };

    #undef CHECK_ALL_TCP
    #undef GET_TCP_HDR_BY_INDEX
}

// --- protoUdpTrigger ---
void protoUdpTrigger::createNameLambda() {
    std::weak_ptr<protoUdpTrigger> self = shared_from_this();
   
    #define GET_UDP_HDR_BY_INDEX(spt, index, hdr_ptr) \
        const ProtocolInfo* info = findNthProtocol(spt->m_protoStack, IPPROTO_UDP, index); \
        if (!info || !info->data_ptr) return 0; \
        const udphdr* hdr_ptr = reinterpret_cast<const udphdr*>(info->data_ptr);

    /**
     * @brief Returns the UDP length field.
     * @param index (optional) 0=all (returns first found), 1=first, 2=second, etc.
     */
    m_protoMap["UDP.Length"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            int index = (args.empty() || args[0] == 0) ? 1 : args[0]; // Default to first
            GET_UDP_HDR_BY_INDEX(spt, index, udp);
            #ifdef __linux__
            return (int)ntohs(udp->uh_ulen);
            #else
            return (int)ntohs(udp->uh_len);
            #endif
        } return 0;
    };
   
    #undef GET_UDP_HDR_BY_INDEX
}

// --- protoIpv4Trigger ---
void protoIpv4Trigger::createNameLambda() {
    std::weak_ptr<protoIpv4Trigger> self = shared_from_this();
   
    #define GET_IP_HDR_BY_INDEX(spt, index, hdr_ptr) \
        const ProtocolInfo* info = findNthProtocol(spt->m_protoStack, ETHERTYPE_IP, index); \
        if (!info || !info->data_ptr) return 0; \
        const ip* hdr_ptr = reinterpret_cast<const ip*>(info->data_ptr);

    /**
     * @brief Returns the IPv4 Total Length field.
     * @param index (optional) 0=all (returns first found), 1=first, 2=second, etc.
     */
    m_protoMap["IP.TotalLen"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            int index = (args.empty() || args[0] == 0) ? 1 : args[0]; // Default to first
            GET_IP_HDR_BY_INDEX(spt, index, ip_hdr);
            return (int)ntohs(ip_hdr->ip_len);
        } return 0;
    };
   
    /**
     * @brief Returns the IPv4 Header Length in bytes.
     * @param index (optional) 0=all (returns first found), 1=first, 2=second, etc.
     */
    m_protoMap["IP.HeaderLen"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            int index = (args.empty() || args[0] == 0) ? 1 : args[0]; // Default to first
            GET_IP_HDR_BY_INDEX(spt, index, ip_hdr);
            return (int)(ip_hdr->ip_hl * 4);
        } return 0;
    };
   
    /**
     * @brief Returns the IPv4 Time-to-Live (TTL) value.
     * @param index (optional) 0=all (returns first found), 1=first, 2=second, etc.
     */
    m_protoMap["IP.TTL"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            int index = (args.empty() || args[0] == 0) ? 1 : args[0]; // Default to first
            GET_IP_HDR_BY_INDEX(spt, index, ip_hdr);
            return (int)(ip_hdr->ip_ttl);
        } return 0;
    };

    /**
     * @brief Returns the IPv4 Protocol field (e.g., 6 for TCP, 17 for UDP).
     * @param index (optional) 0=all (returns first found), 1=first, 2=second, etc.
     */
    m_protoMap["IP.Proto"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            int index = (args.empty() || args[0] == 0) ? 1 : args[0]; // Default to first
            GET_IP_HDR_BY_INDEX(spt, index, ip_hdr);
            return (int)(ip_hdr->ip_p);
        } return 0;
    };

    #undef GET_IP_HDR_BY_INDEX
}

// --- protoIcmpTrigger ---
void protoIcmpTrigger::createNameLambda() {
    std::weak_ptr<protoIcmpTrigger> self = shared_from_this();

    // Helper macro to get ICMP header by index
    #define GET_ICMP_HDR_BY_INDEX(spt, index, hdr_ptr) \
        const ProtocolInfo* info = findNthProtocol(spt->m_protoStack, IPPROTO_ICMP, index); \
        if (!info || !info->data_ptr) return 0; \
        const icmp* hdr_ptr = reinterpret_cast<const icmp*>(info->data_ptr);

    /**
     * @brief Returns the ICMP Type value. (e.g., 8 for Ping Request)
     * @param index (optional) 0=all (returns first found), 1=first, 2=second, etc.
     */
    m_protoMap["ICMP.Type"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            int index = (args.empty() || args[0] == 0) ? 1 : args[0];
            GET_ICMP_HDR_BY_INDEX(spt, index, ic_hdr);
            return (int)ic_hdr->icmp_type;
        } return 0;
    };
   
    /**
     * @brief Returns the ICMP Code value.
     * @param index (optional) 0=all (returns first found), 1=first, 2=second, etc.
     */
    m_protoMap["ICMP.Code"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            int index = (args.empty() || args[0] == 0) ? 1 : args[0];
            GET_ICMP_HDR_BY_INDEX(spt, index, ic_hdr);
            return (int)ic_hdr->icmp_code;
        } return 0;
    };

    #undef GET_ICMP_HDR_BY_INDEX
}

// --- protoGreTrigger ---
void protoGreTrigger::createNameLambda() {
    std::weak_ptr<protoGreTrigger> self = shared_from_this();
    /**
     * @brief Returns 1 if GRE protocol is present at the specified index.
     * @param index (optional) 0=all (returns 1 if ANY exist), 1=first, 2=second, etc.
     */
    m_protoMap["GRE.IsPresent"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            int index = (args.empty() ? 0 : args[0]);
            // --- FIX: Explicit cast to int to resolve type ambiguity ---
            return (int)(findNthProtocol(spt->m_protoStack, IPPROTO_GRE, index) != nullptr);
        } return 0;
    };
}

// --- protoDnsTrigger ---
void protoDnsTrigger::createNameLambda() {
    std::weak_ptr<protoDnsTrigger> self = shared_from_this();
    m_protoMap["DNS.IsQuery"] = [self](const std::vector<int>&) {
        return 0; // Placeholder
    };
}

// --- protoTlsTrigger ---
void protoTlsTrigger::createNameLambda() {
    std::weak_ptr<protoTlsTrigger> self = shared_from_this();
    m_protoMap["TLS.HasSNI"] = [self](const std::vector<int>&) {
        return 0; // Placeholder
    };
}

} //end namespace
