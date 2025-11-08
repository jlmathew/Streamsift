/**
 * @file PacketStreamEval.h
 * @brief Defines the PacketStreamEval class, which manages a single packet stream.
 * @version 0.9.2
 */

/*
 * Author: James Mathewson
 * Date: 6 November 2025
 * Version: 0.7 beta
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
#include "ProtoTrigger.h" // Needs protoTrigger definition
#include "pcapparser.h"   // For ASTNode
#include "ConfigParser.h" // For TimeoutMap

// Forward declarations
struct PacketOffsets_t;
struct pcap_pkthdr;

namespace pcapabvparser {

/// Type alias for the map holding protocol-specific trigger objects.
using ProtoTriggerMap = PluggableUnorderedMap<std::string, std::shared_ptr<protoTrigger>>;
using Func = std::function<int(const std::vector<int>&)>;

/**
 * @enum StreamMode
 * @brief Defines how a stream's packets should be stored.
 */
enum class StreamMode {
    COMBINED,
    SEPARATE
};

/**
 * @class PacketStreamEval
 * @brief Manages the state, packets, and stats for a single packet stream (5-tuple).
 */
class PacketStreamEval {
public:
    PacketStreamEval();
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

    using PacketBuffer = std::deque<std::pair<std::unique_ptr<pcap_pkthdr>, std::unique_ptr<uint8_t[]>>>;

    void transferPacketToBuffer(
        PacketBuffer& buffer,
        bool& triggerSeen,
        uint32_t& postPktCnt,
        size_t& bufferedBytes,
        std::unique_ptr<pcap_pkthdr>&& header, 
        std::unique_ptr<uint8_t[]>&& data
    );

    void flushBufferToFile(PacketBuffer& buffer, size_t& bufferedBytes, const std::string& filename);
    void bindAstRecursive(ASTNode* node);
    void determineTimeout(const TimeoutMap& timeoutMap);

    // --- Member Variables ---

    std::string m_id;
    std::string m_fileNameBase;

    ProtoTriggerMap m_protocolsUsed;
    std::unique_ptr<ASTNode> m_boundTagAst;
    std::unique_ptr<ASTNode> m_boundSaveAst;
    bool m_saveFilterIsSameAsTagFilter;
    bool m_saveFilterMatched;
    
    /// True if the .detected file has already been created for this stream.
    bool m_detectedFileCreated; // <-- NEW

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
    
    std::vector<uint64_t> m_interPacketGaps;
    mutable std::mutex m_gapVectorMutex;
    timeval m_lastPacketTimestamp;

    const std::vector<uint64_t> m_latencyBuckets = 
        { 10, 50, 100, 250, 500, 1000, 5000, 10000, 50000, 100000 };
    mutable std::map<uint64_t, uint64_t> m_latencyHistogram;
};

} // namespace pcapabvparser
#endif // __PACKET_STREAM_EVAL_H__
