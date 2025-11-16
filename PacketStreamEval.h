/**
 * @file PacketStreamEval.h
 * @brief Added consumer ID tracking for debug correlation.
 */
#ifndef __PACKET_STREAM_EVAL_H__
#define __PACKET_STREAM_EVAL_H__

#include <string>
#include <vector>
#include <memory>
#include <deque>
#include <pcap/pcap.h>
#include <cstdint>
#include <atomic>
#include <mutex>
#include <map>

#include "PluggableMap.h"
#include "ProtoTrigger.h"
#include "pcapparser.h"
#include "ConfigParser.h"

struct PacketOffsets_t;
struct pcap_pkthdr;

namespace pcapabvparser {

using ProtoTriggerMap = PluggableUnorderedMap<std::string, std::shared_ptr<protoTrigger>>;
using Func = std::function<int(const std::vector<int>&)>;

enum class StreamMode { COMBINED, SEPARATE };

class PacketStreamEval {
public:
    // --- CHANGED: Constructor takes consumer ID ---
    PacketStreamEval(size_t consumerId);
    virtual ~PacketStreamEval();

    void registerAndBindAST(const ASTNode* tagRoot, const ASTNode* saveRoot, const TimeoutMap& timeoutMap);
    void setId(const std::string& id);
    void evaluatePacket(pcap_pkthdr* hdr, uint8_t* data, PacketOffsets_t* offsets, const ProtocolStack_t* stack);
    void transferPacket(std::unique_ptr<pcap_pkthdr>&& header, std::unique_ptr<uint8_t[]>&& data, bool isIngress);
    void flushPacketsToDisk();
    void cleanupOnExpiry();
    std::chrono::seconds getTimeout() const { return m_myTimeout; }

private:
    void printSummary() const;
    // --- NEW: Debug dumper for Python correlation ---
    void printDebugStreamInfo() const;

    using PacketBuffer = std::deque<std::pair<std::unique_ptr<pcap_pkthdr>, std::unique_ptr<uint8_t[]>>>;

    void transferPacketToBuffer(PacketBuffer& buffer, bool& triggerSeen, uint32_t& postPktCnt, size_t& bufferedBytes, std::unique_ptr<pcap_pkthdr>&& header, std::unique_ptr<uint8_t[]>&& data);
    void flushBufferToFile(PacketBuffer& buffer, size_t& bufferedBytes, const std::string& baseFilename);
    void bindAstRecursive(ASTNode* node);
    void determineTimeout(const TimeoutMap& timeoutMap);
    void mergePartialFiles(const std::string& finalFilename, const std::vector<std::string>& parts);

    std::string m_id;
    std::string m_fileNameBase;
    size_t m_consumerId; // --- NEW ---

    ProtoTriggerMap m_protocolsUsed;
    std::unique_ptr<ASTNode> m_boundTagAst;
    std::unique_ptr<ASTNode> m_boundSaveAst;
    bool m_saveFilterIsSameAsTagFilter;
    bool m_saveFilterMatched;
    bool m_detectedFileCreated;

    PluggableUnorderedMap<std::string, Func> m_errorFuncs;
    StreamMode m_streamMode;

    PacketBuffer m_packetHistory_ingress;
    PacketBuffer m_packetHistory_egress;

    const uint32_t m_prePacketHistoryMax;
    const uint32_t m_postPacketHistoryMax;

    bool m_triggerPacketSeen_ingress;
    uint32_t m_currentPostPacketHistoryCnt_ingress;
    size_t m_bufferedBytes_ingress;

    bool m_triggerPacketSeen_egress;
    uint32_t m_currentPostPacketHistoryCnt_egress;
    size_t m_bufferedBytes_egress;

    const size_t m_flushThresholdBytes;
    std::chrono::seconds m_myTimeout;

    std::atomic<uint64_t> m_totalPacketsReceived{0};
    std::atomic<uint64_t> m_totalBytesReceived{0};
    std::atomic<uint64_t> m_totalPacketsSaved{0};

    uint32_t m_flushSequence{0};
    std::vector<std::string> m_createdFiles;

    std::vector<uint64_t> m_interPacketGaps;
    mutable std::mutex m_gapVectorMutex;
    timeval m_lastPacketTimestamp;

    const std::vector<uint64_t> m_latencyBuckets = { 10, 50, 100, 250, 500, 1000, 5000, 10000, 50000, 100000 };
    mutable std::map<uint64_t, uint64_t> m_latencyHistogram;
};

}
#endif // __PACKET_STREAM_EVAL_H__
