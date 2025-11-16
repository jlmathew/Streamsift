/**
 * @file PacketStreamEval.cpp
 * @author James Mathewson
 * @version 1.1.2 (Compilable + Buffer Math Fix)
 * @brief Implementation of PacketStreamEval.
 */

#include "PacketStreamEval.h"
#include "pcap_abbv_cli_parser.h" // Required for globalOptions
#include "Logger.h"
#include "Globals.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <fstream>

#define DEBUG_EVAL

#ifdef DEBUG_EVAL
    #define LOG_DEBUG(msg) Logger::log("[DEBUG][EVAL] " + std::string(msg))
#else
    #define LOG_DEBUG(msg) do {} while(0)
#endif

namespace pcapabvparser {

static std::mutex g_io_mutex;

// --- Helper for TLS Truncation ---
uint32_t performTlsTruncation(uint32_t caplen, uint8_t* data) {
    if (caplen < 54) return caplen;
    size_t offset = 14;
    if (offset >= caplen) return caplen;
    const struct ip* iph = reinterpret_cast<const struct ip*>(data + offset);
    if (iph->ip_v != 4) return caplen;
    size_t ip_hl = iph->ip_hl * 4;
    if (iph->ip_p != IPPROTO_TCP) return caplen;
    offset += ip_hl;
    if (offset + 20 > caplen) return caplen;
    const struct tcphdr* tcph = reinterpret_cast<const struct tcphdr*>(data + offset);
    size_t tcp_hl = tcph->th_off * 4;
    offset += tcp_hl;
    if (offset >= caplen) return caplen;

    uint8_t* payload = data + offset;
    size_t payload_len = caplen - offset;
    size_t processed = 0;
    size_t new_payload_end = 0;

    while (processed + 5 <= payload_len) {
        uint8_t type = payload[processed];
        uint8_t ver_major = payload[processed + 1];
        uint16_t len = ntohs(*reinterpret_cast<uint16_t*>(payload + processed + 3));
        if (ver_major != 3) break;
        size_t record_total_len = 5 + len;
        if (processed + record_total_len > payload_len) break;

        if (type == 0x17) {
            memset(payload + processed + 5, 0, len);
            new_payload_end = processed + 5;
        } else if (type == 0x15) {
            size_t keep = (len >= 2) ? 7 : (5 + len);
            if (len > 2) memset(payload + processed + 7, 0, len - 2);
            new_payload_end = processed + keep;
        } else {
            new_payload_end = processed + record_total_len;
        }
        processed += record_total_len;
    }
    if (processed > 0) return offset + new_payload_end;
    return caplen;
}

PacketStreamEval::PacketStreamEval(size_t consumerId)
    : m_consumerId(consumerId),
      m_saveFilterIsSameAsTagFilter(false),
      m_saveFilterMatched(false),
      m_detectedFileCreated(false),
      m_prePacketHistoryMax(globalOptions.bufferPacketsBefore),
      m_postPacketHistoryMax(globalOptions.bufferPacketsAfter),
      m_triggerPacketSeen_ingress(false),
      m_currentPostPacketHistoryCnt_ingress(0),
      m_bufferedBytes_ingress(0),
      m_triggerPacketSeen_egress(false),
      m_currentPostPacketHistoryCnt_egress(0),
      m_bufferedBytes_egress(0),
      m_flushThresholdBytes(globalOptions.bufferSizePerStreamFlush),
      m_myTimeout(60)
{
    m_streamMode = (globalOptions.streamMode == "separate")
                   ? StreamMode::SEPARATE
                   : StreamMode::COMBINED;
    m_lastPacketTimestamp = {0, 0};
    for(auto bucket : m_latencyBuckets) m_latencyHistogram[bucket] = 0;
}

PacketStreamEval::~PacketStreamEval() {
    LOG_DEBUG("Stream " + m_id + " destroyed.");
}

void PacketStreamEval::setId(const std::string& id) {
    m_id = id;
    m_fileNameBase = globalOptions.preName + "_" + m_id;
}

void PacketStreamEval::registerAndBindAST(const ASTNode* tagRoot, const ASTNode* saveRoot, const TimeoutMap& timeoutMap) {
    m_protocolsUsed["IP"] = protoIpv4Trigger::create();
    m_protocolsUsed["TCP"] = protoTcpTrigger::create();
    m_protocolsUsed["UDP"] = protoUdpTrigger::create();
    m_protocolsUsed["ICMP"] = protoIcmpTrigger::create();
    m_protocolsUsed["GRE"] = protoGreTrigger::create();
    m_protocolsUsed["DNS"] = protoDnsTrigger::create();
    m_protocolsUsed["TLS"] = protoTlsTrigger::create();
    m_protocolsUsed["SMB"] = protoSmbTrigger::create();
    m_protocolsUsed["NFS"] = protoNfsTrigger::create();

    if (tagRoot) {
        m_boundTagAst.reset(tagRoot->clone().release());
        bindAstRecursive(m_boundTagAst.get());
    }
    if (saveRoot == tagRoot) {
        m_saveFilterIsSameAsTagFilter = true;
        m_boundSaveAst = nullptr;
    } else if (saveRoot) {
        m_boundSaveAst.reset(saveRoot->clone().release());
        bindAstRecursive(m_boundSaveAst.get());
    }
    determineTimeout(timeoutMap);
}

void PacketStreamEval::bindAstRecursive(ASTNode* node) {
    if (!node) return;
    if (auto* func = dynamic_cast<FuncCallNode*>(node)) {
        Func* func_ptr = nullptr;
        for (auto const& [name, trigger_ptr] : m_protocolsUsed) {
            func_ptr = trigger_ptr->findFunction(func->name);
            if (func_ptr) break;
        }
        if (func_ptr) func->m_bound_function_ptr = func_ptr;
        else {
             std::string func_name = func->name;
             m_errorFuncs[func_name] = [](const std::vector<int>&){ return 0; };
             func->m_bound_function_ptr = &m_errorFuncs[func_name];
        }
        for (auto& arg : func->args) bindAstRecursive(arg.get());
    } else if (auto* unary = dynamic_cast<UnaryNode*>(node)) {
        bindAstRecursive(unary->operand.get());
    } else if (auto* binary = dynamic_cast<BinaryNode*>(node)) {
        bindAstRecursive(binary->left.get());
        bindAstRecursive(binary->right.get());
    } else if (auto* strNode = dynamic_cast<StringCompareNode*>(node)) {
        StringFunc* func_ptr = nullptr;
        for (auto const& [name, trigger_ptr] : m_protocolsUsed) {
            func_ptr = trigger_ptr->findStringFunction(strNode->funcName);
            if (func_ptr) break;
        }
        if (func_ptr) strNode->m_bound_string_func = func_ptr;
        for(auto& arg : strNode->args) bindAstRecursive(arg.get());
    }
}

void PacketStreamEval::evaluatePacket(pcap_pkthdr* hdr, uint8_t* data, PacketOffsets_t* offsets, const ProtocolStack_t* stack) {
    m_totalPacketsReceived++;
    m_totalBytesReceived += hdr->len;

    for (auto const& [name, trigger_ptr] : m_protocolsUsed) {
        trigger_ptr->setCurrentPacket(offsets, data, stack);
    }

    int tag_result = 0;
    if (m_boundTagAst) tag_result = m_boundTagAst->eval();

    // --- BUFFERING TRIGGER LOGIC ---
    // Fix: Set count to Max + 1, so this trigger packet is saved, plus Max subsequent packets.
    if (tag_result != 0) {
         uint32_t countVal = m_postPacketHistoryMax + 1;

         if (m_streamMode == StreamMode::COMBINED) {
             if (!m_triggerPacketSeen_ingress) {
                 m_triggerPacketSeen_ingress = true;
                 m_currentPostPacketHistoryCnt_ingress = countVal;
             }
         } else {
             if (offsets->originalAddrPortOrdering) {
                 if (!m_triggerPacketSeen_ingress) {
                     m_triggerPacketSeen_ingress = true;
                     m_currentPostPacketHistoryCnt_ingress = countVal;
                 }
             } else {
                 if (!m_triggerPacketSeen_egress) {
                     m_triggerPacketSeen_egress = true;
                     m_currentPostPacketHistoryCnt_egress = countVal;
                 }
             }
         }
    }

    if (!m_saveFilterMatched) {
        if (m_saveFilterIsSameAsTagFilter && tag_result != 0) m_saveFilterMatched = true;
        else if (m_boundSaveAst && m_boundSaveAst->eval() != 0) m_saveFilterMatched = true;

        if (m_saveFilterMatched && globalOptions.createDetectedFile && !m_detectedFileCreated) {
            std::string n = m_fileNameBase + ".detected";
            std::ofstream out(n); out.close(); m_detectedFileCreated = true;
        }
    }

    for (auto const& [name, trigger_ptr] : m_protocolsUsed) {
        trigger_ptr->setCurrentPacket(nullptr, nullptr, nullptr);
    }
}

void PacketStreamEval::transferPacket(std::unique_ptr<pcap_pkthdr>&& header, std::unique_ptr<uint8_t[]>&& data, bool isIngress) {
    if (m_streamMode == StreamMode::COMBINED) {
        transferPacketToBuffer(m_packetHistory_ingress, m_triggerPacketSeen_ingress, m_currentPostPacketHistoryCnt_ingress, m_bufferedBytes_ingress, std::move(header), std::move(data));
    } else {
        if (isIngress) {
            transferPacketToBuffer(m_packetHistory_ingress, m_triggerPacketSeen_ingress, m_currentPostPacketHistoryCnt_ingress, m_bufferedBytes_ingress, std::move(header), std::move(data));
        } else {
            transferPacketToBuffer(m_packetHistory_egress, m_triggerPacketSeen_egress, m_currentPostPacketHistoryCnt_egress, m_bufferedBytes_egress, std::move(header), std::move(data));
        }
    }
}

void PacketStreamEval::transferPacketToBuffer(PacketBuffer& buffer, bool& triggerSeen, uint32_t& postPktCnt, size_t& bufferedBytes, std::unique_ptr<pcap_pkthdr>&& header, std::unique_ptr<uint8_t[]>&& data) {
    size_t packet_size = header->caplen;
    bufferedBytes += packet_size;

    buffer.emplace_back(std::move(header), std::move(data));

    if (!triggerSeen) {
        // Pre-trigger: Keep rolling window
        while (buffer.size() > m_prePacketHistoryMax) {
            bufferedBytes -= buffer.front().first->caplen;
            buffer.pop_front();
        }
    } else {
        // Post-trigger: Decrement always.
        // We initialized to Max+1.
        // Trigger Pkt -> Cnt drops to Max.
        // Post Pkts -> Cnt drops Max->0.
        if (postPktCnt > 0) {
            postPktCnt--;
        }

        if (postPktCnt == 0) {
             triggerSeen = false;
        }
    }

    if (bufferedBytes > m_flushThresholdBytes) {
        flushPacketsToDisk();
    }
}

void PacketStreamEval::flushBufferToFile(PacketBuffer& buffer, size_t& bufferedBytes, const std::string& baseFilename) {
    if (buffer.empty()) return;
    std::lock_guard<std::mutex> lock(g_io_mutex);

    std::string actualFilename = baseFilename + "_part" + std::to_string(m_flushSequence++) + ".pcap";
    m_createdFiles.push_back(actualFilename);

    pcap_t* pd = pcap_open_dead(DLT_EN10MB, 65535);
    pcap_dumper_t* pdumper = pcap_dump_open(pd, actualFilename.c_str());

    for (const auto& pair : buffer) {
        if (globalOptions.truncateTlsData) {
            uint32_t old_len = pair.first->caplen;
            uint32_t new_len = performTlsTruncation(old_len, pair.second.get());
            if (new_len < old_len) {
                pair.first->caplen = new_len;
                pcap_dump(reinterpret_cast<u_char*>(pdumper), pair.first.get(), pair.second.get());
                pair.first->caplen = old_len;
                continue;
            }
        }
        pcap_dump(reinterpret_cast<u_char*>(pdumper), pair.first.get(), pair.second.get());
    }

    pcap_dump_close(pdumper);
    pcap_close(pd);

    m_totalPacketsSaved += buffer.size();
    buffer.clear();
    bufferedBytes = 0;
}

void PacketStreamEval::flushPacketsToDisk() {
    if (m_streamMode == StreamMode::COMBINED) flushBufferToFile(m_packetHistory_ingress, m_bufferedBytes_ingress, m_fileNameBase + ".pcap");
    else {
        flushBufferToFile(m_packetHistory_ingress, m_bufferedBytes_ingress, m_fileNameBase + "_client.pcap");
        flushBufferToFile(m_packetHistory_egress, m_bufferedBytes_egress, m_fileNameBase + "_server.pcap");
    }
}

void PacketStreamEval::cleanupOnExpiry() {
    flushPacketsToDisk();
    printDebugStreamInfo();
    if (globalOptions.streamSummary && m_saveFilterMatched) printSummary();
    std::lock_guard<std::mutex> lock(g_io_mutex);
    if (!m_saveFilterMatched) {
        for (const auto& f : m_createdFiles) std::remove(f.c_str());
        if (m_detectedFileCreated) std::remove((m_fileNameBase + ".detected").c_str());
    } else {
        g_total_streams_saved.fetch_add(1, std::memory_order_relaxed);
        if (globalOptions.mergeOutputFiles && m_streamMode == StreamMode::COMBINED) mergePartialFiles(m_fileNameBase + ".pcap", m_createdFiles);
    }
}

void PacketStreamEval::mergePartialFiles(const std::string& finalFilename, const std::vector<std::string>& parts) {
    if (parts.empty()) return;
    if (parts.size() == 1) { std::rename(parts[0].c_str(), finalFilename.c_str()); return; }
    pcap_t* pd = pcap_open_dead(DLT_EN10MB, 65535);
    pcap_dumper_t* pdumper = pcap_dump_open(pd, finalFilename.c_str());
    char err[PCAP_ERRBUF_SIZE];
    for(const auto& p : parts) {
        pcap_t* pr = pcap_open_offline(p.c_str(), err);
        if(pr){ struct pcap_pkthdr* h; const u_char* d; while(pcap_next_ex(pr, &h, &d)>0) pcap_dump((u_char*)pdumper, h, d); pcap_close(pr); }
        std::remove(p.c_str());
    }
    pcap_dump_close(pdumper); pcap_close(pd);
}

void PacketStreamEval::printDebugStreamInfo() const {
#ifdef DEBUG_EVAL
    std::stringstream ss;
    ss << "STREAM_DEBUG key=" << m_id << " thread=" << m_consumerId << " pkts=" << m_totalPacketsReceived << " saved=" << (m_saveFilterMatched?"1":"0");
    Logger::log(ss.str());
#endif
}

void PacketStreamEval::printSummary() const {
    std::lock_guard<std::mutex> lock(m_gapVectorMutex);
    std::ostringstream oss;
    oss << "\n--- Stream Summary: " << m_id << " ---\n"
        << "  Total Packets Rcvd: " << m_totalPacketsReceived << "\n"
        << "  Total Packets Saved:  " << m_totalPacketsSaved.load() << "\n"
        << "  Save Filter Matched: " << (m_saveFilterMatched ? "YES" : "NO") << "\n";
    Logger::log(oss.str());
}

void PacketStreamEval::determineTimeout(const TimeoutMap& m) {
    auto default_it = m.find(0);
    m_myTimeout = default_it->second;
    if (m_protocolsUsed.count("TCP")) {
        auto it = m.find(IPPROTO_TCP);
        if (it != m.end() && it->second > m_myTimeout) m_myTimeout = it->second;
    } else if (m_protocolsUsed.count("UDP")) {
        auto it = m.find(IPPROTO_UDP);
        if (it != m.end() && it->second > m_myTimeout) m_myTimeout = it->second;
    }
}

}

