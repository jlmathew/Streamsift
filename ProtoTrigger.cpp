/**
 * @file ProtoTrigger.cpp
 * @author James Mathewson
 * @version 1.4.1 (Fix: Braces for Logic Safety)
 * @brief Implementation of triggers with corrected control flow.
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
#include <cstring>
#include <arpa/inet.h>

namespace pcapabvparser {

const ProtocolInfo* findNthProtocol(const ProtocolStack_t* stack, uint32_t proto_type, int index) {
    if (!stack) return nullptr;
    int count = 0;
    for (const auto& info : *stack) {
        if (info.type == proto_type) {
            count++;
            if (index <= 0 || count == index) return &info;
        }
    }
    return nullptr;
}

void protoTcpTrigger::createNameLambda() {
    std::weak_ptr<protoTcpTrigger> self = shared_from_this();

    // FIX: Added braces to all lambda bodies
    m_protoMap["TCP.IsSyn"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            if (auto i = findNthProtocol(spt->m_protoStack, IPPROTO_TCP, 0)) {
                return (((tcphdr*)i->data_ptr)->th_flags & TH_SYN) ? 1 : 0;
            }
        }
        return 0;
    };
    m_protoMap["TCP.IsRst"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            if (auto i = findNthProtocol(spt->m_protoStack, IPPROTO_TCP, 0)) {
                return (((tcphdr*)i->data_ptr)->th_flags & TH_RST) ? 1 : 0;
            }
        }
        return 0;
    };
    m_protoMap["TCP.IsFin"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            if (auto i = findNthProtocol(spt->m_protoStack, IPPROTO_TCP, 0)) {
                return (((tcphdr*)i->data_ptr)->th_flags & TH_FIN) ? 1 : 0;
            }
        }
        return 0;
    };
    m_protoMap["TCP.IsAck"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            if (auto i = findNthProtocol(spt->m_protoStack, IPPROTO_TCP, 0)) {
                return (((tcphdr*)i->data_ptr)->th_flags & TH_ACK) ? 1 : 0;
            }
        }
        return 0;
    };
    m_protoMap["TCP.IsIllegal"] = [self](const std::vector<int>& args) {
        if (auto spt = self.lock()) {
            if (auto i = findNthProtocol(spt->m_protoStack, IPPROTO_TCP, 0)) {
                return (((tcphdr*)i->data_ptr)->th_flags & (TH_SYN|TH_RST)) == (TH_SYN|TH_RST) ? 1 : 0;
            }
        }
        return 0;
    };
    m_protoMap["TCP.WindowSize"] = [self](const std::vector<int>& a) {
        if(auto s=self.lock()) {
            if(auto i=findNthProtocol(s->m_protoStack,IPPROTO_TCP,0)) return (int)ntohs(((tcphdr*)i->data_ptr)->th_win);
        }
        return 0;
    };
    m_protoMap["TCP.SrcPort"] = [self](const std::vector<int>& a) {
        if(auto s=self.lock()) {
            if(auto i=findNthProtocol(s->m_protoStack,IPPROTO_TCP,0)) return (int)ntohs(((tcphdr*)i->data_ptr)->th_sport);
        }
        return 0;
    };
    m_protoMap["TCP.DstPort"] = [self](const std::vector<int>& a) {
        if(auto s=self.lock()) {
            if(auto i=findNthProtocol(s->m_protoStack,IPPROTO_TCP,0)) return (int)ntohs(((tcphdr*)i->data_ptr)->th_dport);
        }
        return 0;
    };
    m_protoMap["TCP.IsClientPacket"] = [self](const std::vector<int>& a) {
        if(auto s=self.lock()) {
            if(s->m_packetLayerHelper) return (int)s->m_packetLayerHelper->originalAddrPortOrdering;
        }
        return 0;
    };

    // ROBUST SNI PARSER
    m_stringMap["TLS.Sni"] = [self](const std::vector<int>& a) -> std::string_view {
        if(auto s=self.lock()){
            auto* info = findNthProtocol(s->m_protoStack, PROTO_TLS, 0);
            if (!info || info->payload_length < 10) return "";
            const uint8_t* data = info->data_ptr;
            size_t len = info->payload_length;

            // Scan for Extension 0x0000 (SNI)
            // Start offset 40 skips standard Record+Handshake headers
            for (size_t i = 40; i < len - 5; ++i) {
                if (data[i] == 0x00 && data[i+1] == 0x00) {
                    size_t ext_len = (data[i+2] << 8) | data[i+3];
                    if (i + 4 + ext_len <= len) {
                         // SNI Structure: ListLen(2) + NameType(1) + NameLen(2) + Name...
                         if (i + 9 < len) {
                             uint8_t type = data[i+6];
                             size_t name_len = (data[i+7] << 8) | data[i+8];
                             if (type == 0x00 && i + 9 + name_len <= len) {
                                 return std::string_view(reinterpret_cast<const char*>(data + i + 9), name_len);
                             }
                         }
                    }
                }
            }
        }
        return "";
    };
}

void protoUdpTrigger::createNameLambda() {
    std::weak_ptr<protoUdpTrigger> s = shared_from_this();
    m_protoMap["UDP.Length"] = [s](const std::vector<int>& a) {
        if(auto p=s.lock()) {
            if(auto i=findNthProtocol(p->m_protoStack,IPPROTO_UDP,0)) return (int)ntohs(((udphdr*)i->data_ptr)->uh_ulen);
        }
        return 0;
    };
}

void protoIpv4Trigger::createNameLambda() {
    std::weak_ptr<protoIpv4Trigger> s = shared_from_this();
    #define GET_IP(s, idx) findNthProtocol(s->m_protoStack, ETHERTYPE_IP, (idx==0)?1:idx)
    m_protoMap["IP.TotalLen"] = [s](const std::vector<int>& a) {
        int idx=(a.size()>0)?a[0]:0;
        if(auto p=s.lock()) {
            if(auto* i=GET_IP(p,idx)) return (int)ntohs(((ip*)i->data_ptr)->ip_len);
        }
        return 0;
    };
    m_protoMap["IP.TTL"] = [s](const std::vector<int>& a) {
        int idx=(a.size()>0)?a[0]:0;
        if(auto p=s.lock()) {
            if(auto* i=GET_IP(p,idx)) return (int)((ip*)i->data_ptr)->ip_ttl;
        }
        return 0;
    };
    m_protoMap["IP.Proto"] = [s](const std::vector<int>& a) {
        int idx=(a.size()>0)?a[0]:0;
        if(auto p=s.lock()) {
            if(auto* i=GET_IP(p,idx)) return (int)((ip*)i->data_ptr)->ip_p;
        }
        return 0;
    };
    #undef GET_IP
}

void protoIcmpTrigger::createNameLambda() {
    std::weak_ptr<protoIcmpTrigger> s = shared_from_this();
    m_protoMap["ICMP.Type"] = [s](const std::vector<int>& a) {
        if(auto p=s.lock()) {
            if(p->m_packetLayerHelper) return (int)p->m_packetLayerHelper->icmp_type;
        }
        return 0;
    };
    m_protoMap["ICMP.Code"] = [s](const std::vector<int>& a) {
        if(auto p=s.lock()) {
            if(p->m_packetLayerHelper) return (int)p->m_packetLayerHelper->icmp_code;
        }
        return 0;
    };
}

void protoGreTrigger::createNameLambda() {
    std::weak_ptr<protoGreTrigger> s = shared_from_this();
    m_protoMap["GRE.IsPresent"] = [s](const std::vector<int>& a) {
        if(auto p=s.lock()) {
            return (findNthProtocol(p->m_protoStack,IPPROTO_GRE,0)!=nullptr) ? 1 : 0;
        }
        return 0;
    };
}

void protoDnsTrigger::createNameLambda() {
    std::weak_ptr<protoDnsTrigger> self = shared_from_this();
    auto get_dns_flags = [](const ProtocolInfo* info, bool is_tcp) -> uint16_t {
        size_t offset = is_tcp ? 2 : 0;
        if (!info || info->payload_length < offset + 4) return 0;
        return ntohs(*reinterpret_cast<const uint16_t*>(info->data_ptr + offset + 2));
    };
    m_protoMap["DNS.IsQuery"] = [self, get_dns_flags](const std::vector<int>& a) {
        if(auto s=self.lock()) {
            if(auto* i=findNthProtocol(s->m_protoStack, PROTO_DNS, 0)) {
                bool is_tcp = (s->m_packetLayerHelper->ip_protocol == IPPROTO_TCP);
                return (int)((get_dns_flags(i, is_tcp) & 0x8000) == 0);
            }
        }
        return 0;
    };
    m_protoMap["DNS.IsResponse"] = [self, get_dns_flags](const std::vector<int>& a) {
        if(auto s=self.lock()) {
            if(auto* i=findNthProtocol(s->m_protoStack, PROTO_DNS, 0)) {
                bool is_tcp = (s->m_packetLayerHelper->ip_protocol == IPPROTO_TCP);
                return (int)((get_dns_flags(i, is_tcp) & 0x8000) != 0);
            }
        }
        return 0;
    };
}

void protoTlsTrigger::createNameLambda() {
    std::weak_ptr<protoTlsTrigger> s = shared_from_this();
    m_protoMap["TLS.IsHandshake"] = [s](const std::vector<int>& a) {
        if(auto p=s.lock()) {
            if(auto* i=findNthProtocol(p->m_protoStack, PROTO_TLS, 0)) {
                if(i->payload_length>0) return (int)(*(i->data_ptr) == 0x16);
            }
        }
        return 0;
    };
    m_protoMap["TLS.Version"] = [s](const std::vector<int>& a) {
        if(auto p=s.lock()) {
            if(auto* i=findNthProtocol(p->m_protoStack, PROTO_TLS, 0)) {
                if(i->payload_length>=3) return (int)ntohs(*reinterpret_cast<const uint16_t*>(i->data_ptr + 1));
            }
        }
        return 0;
    };
}

void protoSmbTrigger::createNameLambda() {
    std::weak_ptr<protoSmbTrigger> s = shared_from_this();
    m_protoMap["SMB.Command"] = [s](const std::vector<int>& a) {
        if(auto p=s.lock()) {
            if(auto* i=findNthProtocol(p->m_protoStack, PROTO_SMB, 0)) {
                if(i->payload_length>16 && i->data_ptr[4]==0xFE) return (int)i->data_ptr[4+12];
            }
        }
        return 0;
    };
}

void protoNfsTrigger::createNameLambda() {
    std::weak_ptr<protoNfsTrigger> s = shared_from_this();
    m_protoMap["NFS.IsRead"] = [s](const std::vector<int>& a) { return 0; };
}

} // namespace
