/**
 * @file ProtoTrigger.cpp
 * @author James Mathewson
 * @version 1.1.0 beta (String Support)
 * @brief Implementation of triggers with zero-copy string matching.
 */

#include "ProtoTrigger.h"
#include "pcapparser.h"
#include "Logger.h"
#include "pcapkey.h"
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <iostream>
#include <arpa/inet.h>
#include <cstring> // For memset, etc.

// #define DEBUG_PROTO
#ifdef DEBUG_PROTO
    #define LOG_PROTO(msg) Logger::log("[DEBUG][PROTO] " + std::string(msg))
#else
    #define LOG_PROTO(msg) do {} while(0)
#endif

namespace pcapabvparser {

const ProtocolInfo* findNthProtocol(const ProtocolStack_t* stack, uint32_t proto_type, int index) {
    if (!stack) return nullptr;
    int count = 0;
    for (const auto& info : *stack) {
        if (info.type == proto_type) {
            count++;
            // Index 0 means "first found"
            if (index <= 0 || count == index) return &info;
        }
    }
    return nullptr;
}

// --- protoTcpTrigger ---
void protoTcpTrigger::createNameLambda() {
    std::weak_ptr<protoTcpTrigger> self = shared_from_this();

    #define GET_TCP_HDR_BY_INDEX(spt, index, hdr_ptr) \
        const ProtocolInfo* info = findNthProtocol(spt->m_protoStack, IPPROTO_TCP, index); \
        if (!info || !info->data_ptr) return def; \
        const tcphdr* hdr_ptr = reinterpret_cast<const tcphdr*>(info->data_ptr);

    #define CHECK_ALL_TCP(spt, check_name, check_expr) \
        if (!spt->m_protoStack) return 0; \
        for (const auto& info : *spt->m_protoStack) { \
            if (info.type == IPPROTO_TCP) { \
                const tcphdr* tcp = reinterpret_cast<const tcphdr*>(info.data_ptr); \
                if (check_expr) return 1; \
            } \
        } \
        return 0;

    #define GET_ARGS(a, idx_var, def_var) \
        int idx_var = (a.size() > 0) ? a[0] : 0; \
        int def_var = (a.size() > 1) ? a[1] : 0;

    m_protoMap["TCP.IsSyn"] = [self](const std::vector<int>& args) {
        GET_ARGS(args, idx, def);
        if (auto spt = self.lock()) {
            if (idx == 0) { CHECK_ALL_TCP(spt, "TCP.IsSyn", tcp->th_flags & TH_SYN); }
            else { GET_TCP_HDR_BY_INDEX(spt, idx, tcp); return (int)(tcp->th_flags & TH_SYN); }
        } return def;
    };
    m_protoMap["TCP.IsRst"] = [self](const std::vector<int>& args) {
        GET_ARGS(args, idx, def);
        if (auto spt = self.lock()) {
            if (idx == 0) { CHECK_ALL_TCP(spt, "TCP.IsRst", tcp->th_flags & TH_RST); }
            else { GET_TCP_HDR_BY_INDEX(spt, idx, tcp); return (int)(tcp->th_flags & TH_RST); }
        } return def;
    };
    m_protoMap["TCP.IsFin"] = [self](const std::vector<int>& args) {
        GET_ARGS(args, idx, def);
        if (auto spt = self.lock()) {
            if (idx == 0) { CHECK_ALL_TCP(spt, "TCP.IsFin", tcp->th_flags & TH_FIN); }
            else { GET_TCP_HDR_BY_INDEX(spt, idx, tcp); return (int)(tcp->th_flags & TH_FIN); }
        } return def;
    };
    m_protoMap["TCP.IsAck"] = [self](const std::vector<int>& args) {
        GET_ARGS(args, idx, def);
        if (auto spt = self.lock()) {
            if (idx == 0) { CHECK_ALL_TCP(spt, "TCP.IsAck", tcp->th_flags & TH_ACK); }
            else { GET_TCP_HDR_BY_INDEX(spt, idx, tcp); return (int)(tcp->th_flags & TH_ACK); }
        } return def;
    };
    m_protoMap["TCP.IsIllegal"] = [self](const std::vector<int>& args) {
        GET_ARGS(args, idx, def);
        if (auto spt = self.lock()) {
            if (idx == 0) { CHECK_ALL_TCP(spt, "TCP.IsIllegal", (tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_RST)); }
            else { GET_TCP_HDR_BY_INDEX(spt, idx, tcp); return (int)((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_RST)); }
        } return def;
    };
    m_protoMap["TCP.WindowSize"] = [self](const std::vector<int>& args) {
        GET_ARGS(args, idx_in, def);
        int idx = (idx_in == 0) ? 1 : idx_in; // Default to 1 for numeric
        if (auto spt = self.lock()) {
            GET_TCP_HDR_BY_INDEX(spt, idx, tcp); return (int)ntohs(tcp->th_win);
        } return def;
    };
    m_protoMap["TCP.SrcPort"] = [self](const std::vector<int>& args) {
        GET_ARGS(args, idx_in, def);
        int idx = (idx_in == 0) ? 1 : idx_in;
        if (auto spt = self.lock()) {
            GET_TCP_HDR_BY_INDEX(spt, idx, tcp); return (int)ntohs(tcp->th_sport);
        } return def;
    };
    m_protoMap["TCP.DstPort"] = [self](const std::vector<int>& args) {
        GET_ARGS(args, idx_in, def);
        int idx = (idx_in == 0) ? 1 : idx_in;
        if (auto spt = self.lock()) {
            GET_TCP_HDR_BY_INDEX(spt, idx, tcp); return (int)ntohs(tcp->th_dport);
        } return def;
    };
    m_protoMap["TCP.IsClientPacket"] = [self](const std::vector<int>& args) {
        GET_ARGS(args, idx, def);
        if (auto spt = self.lock()) { if (!spt->m_packetLayerHelper) return def; return (int)(spt->m_packetLayerHelper->originalAddrPortOrdering); } return def;
    };

    // --- String Lambdas (Placeholder registration for new Phase) ---
    m_stringMap["TLS.Sni"] = [self](const std::vector<int>& args) -> std::string_view { return ""; };
    #undef CHECK_ALL_TCP
    #undef GET_TCP_HDR_BY_INDEX
    #undef GET_ARGS
}

// --- protoUdpTrigger ---
void protoUdpTrigger::createNameLambda() {
    std::weak_ptr<protoUdpTrigger> s = shared_from_this();
    m_protoMap["UDP.Length"] = [s](const std::vector<int>& a) {
        int idx=(a.empty()||a[0]==0)?1:a[0];
        int def=(a.size()>1)?a[1]:0;
        if(auto p=s.lock()){
            if(const ProtocolInfo* info=findNthProtocol(p->m_protoStack,IPPROTO_UDP,idx)){
                #ifdef __linux__
                return (int)ntohs(((udphdr*)info->data_ptr)->uh_ulen);
                #else
                return (int)ntohs(((udphdr*)info->data_ptr)->uh_len);
                #endif
            }
        } return def;
    };
}

// --- protoIpv4Trigger ---
void protoIpv4Trigger::createNameLambda() {
    std::weak_ptr<protoIpv4Trigger> self = shared_from_this();
    #define GET_IP(s, idx) findNthProtocol(s->m_protoStack, ETHERTYPE_IP, (idx==0)?1:idx)

    m_protoMap["IP.TotalLen"] = [self](const std::vector<int>& a) {
        int idx=(a.size()>0)?a[0]:0; int def=(a.size()>1)?a[1]:0;
        if(auto s=self.lock()){ if(auto* i=GET_IP(s,idx)) return (int)ntohs(((ip*)i->data_ptr)->ip_len); } return def;
    };
    m_protoMap["IP.TTL"] = [self](const std::vector<int>& a) {
        int idx=(a.size()>0)?a[0]:0; int def=(a.size()>1)?a[1]:0;
        if(auto s=self.lock()){ if(auto* i=GET_IP(s,idx)) return (int)((ip*)i->data_ptr)->ip_ttl; } return def;
    };
    m_protoMap["IP.Proto"] = [self](const std::vector<int>& a) {
        int idx=(a.size()>0)?a[0]:0; int def=(a.size()>1)?a[1]:0;
        if(auto s=self.lock()){ if(auto* i=GET_IP(s,idx)) return (int)((ip*)i->data_ptr)->ip_p; } return def;
    };
    #undef GET_IP
}

// --- protoIcmpTrigger ---
void protoIcmpTrigger::createNameLambda() {
    std::weak_ptr<protoIcmpTrigger> s = shared_from_this();
    m_protoMap["ICMP.Type"] = [s](const std::vector<int>& a) { int def=(a.size()>1)?a[1]:0; if(auto p=s.lock()){ if(p->m_packetLayerHelper) return (int)p->m_packetLayerHelper->icmp_type; } return def; };
    m_protoMap["ICMP.Code"] = [s](const std::vector<int>& a) { int def=(a.size()>1)?a[1]:0; if(auto p=s.lock()){ if(p->m_packetLayerHelper) return (int)p->m_packetLayerHelper->icmp_code; } return def; };
}

// --- protoGreTrigger ---
void protoGreTrigger::createNameLambda() {
    std::weak_ptr<protoGreTrigger> s = shared_from_this();
    m_protoMap["GRE.IsPresent"] = [s](const std::vector<int>& a) {
        int idx=(a.size()>0)?a[0]:0; int def=(a.size()>1)?a[1]:0;
        if(auto p=s.lock()){ return (findNthProtocol(p->m_protoStack,IPPROTO_GRE,idx)!=nullptr) ? 1 : 0; } return def;
    };
}

// --- L7 Integer Triggers ---

void protoDnsTrigger::createNameLambda() {
    std::weak_ptr<protoDnsTrigger> self = shared_from_this();
    auto get_dns_flags = [](const ProtocolInfo* info, bool is_tcp) -> uint16_t {
        size_t min_len = is_tcp ? 4 : 4;
        if (!info || info->payload_length < min_len) return 0;
        const uint8_t* ptr = info->data_ptr;
        if (is_tcp) ptr += 2;
        return ntohs(*reinterpret_cast<const uint16_t*>(ptr + 2));
    };
    m_protoMap["DNS.IsQuery"] = [self, get_dns_flags](const std::vector<int>& a) {
        int idx=(a.empty())?0:a[0]; int def=(a.size()>1)?a[1]:0;
        if(auto s=self.lock()){
            if(auto* i=findNthProtocol(s->m_protoStack, PROTO_DNS, idx)) {
                bool is_tcp = (s->m_packetLayerHelper->ip_protocol == IPPROTO_TCP);
                return (int)((get_dns_flags(i, is_tcp) & 0x8000) == 0);
            }
        } return def;
    };
     m_protoMap["DNS.IsResponse"] = [self, get_dns_flags](const std::vector<int>& a) {
        int idx=(a.empty())?0:a[0]; int def=(a.size()>1)?a[1]:0;
        if(auto s=self.lock()){
            if(auto* i=findNthProtocol(s->m_protoStack, PROTO_DNS, idx)) {
                bool is_tcp = (s->m_packetLayerHelper->ip_protocol == IPPROTO_TCP);
                return (int)((get_dns_flags(i, is_tcp) & 0x8000) != 0);
            }
        } return def;
    };
}

void protoTlsTrigger::createNameLambda() {
    std::weak_ptr<protoTlsTrigger> self = shared_from_this();

    // --- INTEGER LAMBDAS ---
    m_protoMap["TLS.IsHandshake"] = [self](const std::vector<int>& a) {
        int idx=(a.empty())?0:a[0]; int def=(a.size()>1)?a[1]:0;
        if(auto s=self.lock()){
            if(auto* i=findNthProtocol(s->m_protoStack, PROTO_TLS, idx)) {
                 if(i->payload_length > 0 && i->data_ptr) {
                     return (int)(*(i->data_ptr) == 0x16); // 0x16 = Handshake
                 }
            }
        } return def;
    };
    m_protoMap["TLS.Version"] = [self](const std::vector<int>& a) {
        int idx=(a.empty())?0:a[0]; int def=(a.size()>1)?a[1]:0;
        if(auto s=self.lock()){
            if(auto* i=findNthProtocol(s->m_protoStack, PROTO_TLS, idx)) {
                 if(i->payload_length >= 3) {
                     return (int)ntohs(*reinterpret_cast<const uint16_t*>(i->data_ptr + 1));
                 }
            }
        } return def;
    };

    // --- NEW: STRING LAMBDAS ---
    m_stringMap["TLS.Sni"] = [self](const std::vector<int>& a) -> std::string_view {
        if(auto s=self.lock()){
            int idx = (a.empty()) ? 0 : a[0];
            auto* info = findNthProtocol(s->m_protoStack, PROTO_TLS, idx);
            if (!info || info->payload_length < 43) return ""; // Min length for ClientHello

            const uint8_t* data = info->data_ptr;
            size_t len = info->payload_length;

            // 1. Check Record Type (0x16 Handshake) & Version (0x03XX)
            if (data[0] != 0x16 || data[1] != 0x03) return "";

            // 2. Skip Record Header (5 bytes)
            size_t pos = 5;
            // 3. Check Handshake Type (0x01 ClientHello)
            if (pos >= len || data[pos] != 0x01) return "";

            // 4. Skip Handshake Header (4 bytes) + Protocol Version (2 bytes) + Random (32 bytes) = 38 bytes
            pos += 38;
            if (pos >= len) return "";

            // 5. Skip Session ID
            uint8_t sess_id_len = data[pos++];
            pos += sess_id_len;
            if (pos >= len) return "";

            // 6. Skip Cipher Suites
            if (pos + 2 > len) return "";
            uint16_t cipher_len = ntohs(*reinterpret_cast<const uint16_t*>(data + pos));
            pos += 2 + cipher_len;
            if (pos >= len) return "";

            // 7. Skip Compression Methods
            if (pos + 1 > len) return "";
            uint8_t comp_len = data[pos++];
            pos += comp_len;
            if (pos >= len) return "";

            // 8. Extensions
            if (pos + 2 > len) return "";
            uint16_t ext_len_total = ntohs(*reinterpret_cast<const uint16_t*>(data + pos));
            pos += 2;

            size_t end_of_ext = pos + ext_len_total;
            if (end_of_ext > len) end_of_ext = len;

            while (pos + 4 <= end_of_ext) {
                uint16_t ext_type = ntohs(*reinterpret_cast<const uint16_t*>(data + pos));
                uint16_t ext_len = ntohs(*reinterpret_cast<const uint16_t*>(data + pos + 2));
                pos += 4;

                if (ext_type == 0x0000) { // Server Name
                    // Inside SNI extension: List Length (2 bytes)
                    if (pos + 2 <= end_of_ext) {
                        pos += 2;
                        // Inside List: Name Type (1 byte) + Name Len (2 bytes) + Name
                        while (pos + 3 <= end_of_ext) {
                            uint8_t name_type = data[pos];
                            uint16_t name_len = ntohs(*reinterpret_cast<const uint16_t*>(data + pos + 1));
                            pos += 3;

                            if (name_type == 0x00 && pos + name_len <= end_of_ext) {
                                // Found Hostname! Return zero-copy view.
                                return std::string_view(reinterpret_cast<const char*>(data + pos), name_len);
                            }
                            pos += name_len;
                        }
                    }
                    break; // Found SNI block but no hostname? Stop.
                }
                pos += ext_len;
            }
        }
        return "";
    };
}

void protoSmbTrigger::createNameLambda() {
    std::weak_ptr<protoSmbTrigger> self = shared_from_this();
    m_protoMap["SMB.Command"] = [self](const std::vector<int>& a) {
        int idx=(a.empty())?0:a[0]; int def=(a.size()>1)?a[1]:0;
        if(auto s=self.lock()){
            if(auto* i=findNthProtocol(s->m_protoStack, PROTO_SMB, idx)) {
                if(i->payload_length > 16 && i->data_ptr[4] == 0xFE && i->data_ptr[5] == 'S') {
                    return (int)i->data_ptr[4 + 12];
                }
            }
        } return def;
    };
}

void protoNfsTrigger::createNameLambda() {
    std::weak_ptr<protoNfsTrigger> self = shared_from_this();
    m_protoMap["NFS.IsRead"] = [self](const std::vector<int>& a) { int def=(a.size()>1)?a[1]:0; return def; };
}

} //end namespace
