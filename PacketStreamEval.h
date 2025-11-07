/**
 * @file PacketStreamEval.h
 * @brief Defines the PacketStreamEval class, which manages a single packet stream.
 * @version 0.9
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
// Note: ProtocolStack_t is defined in pcapkey.h, which is included by protoTrigger.h

namespace pcapabvparser {

/// Type alias for the map holding protocol-specific trigger objects.
using ProtoTriggerMap = PluggableUnorderedMap<std::string, std::shared_ptr<protoTrigger>>;
using Func = std::function<int(const std::vector<int>&)>;

/**
 * @enum StreamMode
 * @brief Defines how a stream's packets should be stored.
 */
enum class StreamMode {
    /** @brief Store all packets (ingress/egress) in one file. */
    COMBINED,
    /** @brief Store ingress and egress packets in separate _client/_server files. */
    SEPARATE
};

/**
 * @class PacketStreamEval
 * @brief Manages the state, packets, and stats for a single packet stream (5-tuple).
 *
 * This class is responsible for:
 * - Holding the "x-before / y-after" packet history (m_packetHistory).
 * - Evaluating packets against the AST (evaluatePacket).
 * - Storing and flushing triggered packets (transferPacket, flushPacketsToDisk).
 * - Collecting and reporting per-stream statistics (printSummary).
 * - Managing per-direction buffers for "separate" stream mode.
 * - Deleting saved files on expiry if the "Save" filter was not met.
 */
class PacketStreamEval {
public:
    /**
     * @brief Constructor. Initializes state from globalOptions.
     */
    PacketStreamEval();
    
    /**
     * @brief Destructor. Logs destruction.
     */
    virtual ~PacketStreamEval();

    /**
     * @brief Clones the ASTs, binds them, and sets the stream's timeout.
     *
     * This is the main setup function called once when the stream is created.
     *
     * @param tagRoot The root of the "Tag" AST (for x-before/y-after).
     * @param saveRoot The root of the "Save" AST (for final save decision).
     * @param timeoutMap The global map of protocol timeouts.
     */
    void registerAndBindAST(const ASTNode* tagRoot, const ASTNode* saveRoot, const TimeoutMap& timeoutMap);
    
    /**
     * @brief Sets the unique ID and base filename for this stream.
     * @param id The unique string ID (the hex key).
     */
    void setId(const std::string& id);
    
    /**
     * @brief Evaluates a new packet against the *bound* ASTs and updates stats.
     * @param hdr The pcap header for the packet.
     * @param data A pointer to the raw packet data.
     * @param offsets The parsed protocol offsets.
     * @param stack The parsed protocol stack.
     */
    void evaluatePacket(pcap_pkthdr* hdr, uint8_t* data, PacketOffsets_t* offsets, const ProtocolStack_t* stack);
    
    /**
     * @brief Takes ownership of a packet and adds it to the correct internal history deque.
     *
     * This function contains the "x-before / y-after" logic and dispatches
     * to the correct buffer (ingress/egress) based on stream mode.
     *
     * @param header The pcap header (in a unique_ptr).
     * @param data The raw packet data (in a unique_ptr).
     * @param isIngress True if the packet is in the original key direction (client->server).
     */
    void transferPacket(std::unique_ptr<pcap_pkthdr>&& header, std::unique_ptr<uint8_t[]>&& data, bool isIngress);
    
    /**
     * @brief Flushes all buffered packets (both ingress/egress) to their respective files.
     *
     * This is called automatically when a buffer is full, or by cleanupOnExpiry.
     * This function *always* writes to disk if the buffer is not empty.
     * The decision to *keep* the file is made in cleanupOnExpiry.
     */
    void flushPacketsToDisk();
    
    /**
     * @brief Runs final logic on stream expiry.
     *
     * Flushes remaining packets, prints summary, and deletes
     * the save file(s) if the save condition was not met.
     */
    void cleanupOnExpiry();

    /**
     * @brief Gets the configured timeout for this specific stream.
     * @return The timeout duration in seconds.
     */
    std::chrono::seconds getTimeout() const { return m_myTimeout; } // <-- FIX: Added this function

private:
    /**
     * @brief Prints the collected statistics for this stream to the logger.
     */
    void printSummary() const;

    // --- FIX: Moved PacketBuffer definition to be public within 'private' section ---
    // This 'using' must come *before* it is used in the function declarations.
    /**
     * @brief Type alias for the packet history deque.
     */
    using PacketBuffer = std::deque<std::pair<std::unique_ptr<pcap_pkthdr>, std::unique_ptr<uint8_t[]>>>;

    /**
     * @brief Internal helper to manage the x-before/y-after logic for a single buffer.
     * @param buffer The packet buffer (ingress or egress) to add to.
     * @param triggerSeen The trigger flag for this buffer.
     * @param postPktCnt The post-packet counter for this buffer.
     * @param bufferedBytes The byte counter for this buffer.
     * @param header The pcap header.
     * @param data The packet data.
     */
    void transferPacketToBuffer(
        PacketBuffer& buffer, // <-- FIX: Now correctly uses the type
        bool& triggerSeen,
        uint32_t& postPktCnt,
        size_t& bufferedBytes,
        std::unique_ptr<pcap_pkthdr>&& header, 
        std::unique_ptr<uint8_t[]>&& data
    );

    /**
     * @brief Internal helper to flush a single buffer to its file.
     * @param buffer The packet buffer to flush.
     * @param bufferedBytes The byte counter for this buffer.
     * @param filename The file to write/append to.
     */
    void flushBufferToFile(PacketBuffer& buffer, size_t& bufferedBytes, const std::string& filename); // <-- FIX: Now correctly uses the type
    
    /**
     * @brief Recursive helper to bind the AST.
     * @param node The current node in the AST to bind.
     */
    void bindAstRecursive(ASTNode* node);
    
    /**
     * @brief Sets the stream's timeout based on its protocols.
     * @param timeoutMap The global map of protocol timeouts.
     */
    void determineTimeout(const TimeoutMap& timeoutMap);

    // --- Member Variables ---

    std::string m_id;
    std::string m_fileNameBase; // Base name, e-g-, "prefix_ABC123"

    /// Map of protocols used (e.g., "TCP" -> protoTcpTrigger)
    ProtoTriggerMap m_protocolsUsed;
    
    /// This stream's *personal copy* of the "Tag" (Interest) AST.
    std::unique_ptr<ASTNode> m_boundTagAst;
    
    /// This stream's *personal copy* of the "Save" AST.
    std::unique_ptr<ASTNode> m_boundSaveAst;
    
    /// True if the "Save" AST is the same as the "Tag" AST.
    bool m_saveFilterIsSameAsTagFilter;
    
    /// True if any packet in this stream has matched the "Save" filter.
    bool m_saveFilterMatched;

    /// Stores the "error" lambdas for unbound functions.
    PluggableUnorderedMap<std::string, Func> m_errorFuncs;

    /// How to store packets (combined or separate files)
    StreamMode m_streamMode;
    
    PacketBuffer m_packetHistory_ingress; // "Client" packets
    PacketBuffer m_packetHistory_egress;  // "Server" packets

    // "x-before / y-after" logic
    const uint32_t m_prePacketHistoryMax;
    const uint32_t m_postPacketHistoryMax;
    
    // Per-direction state
    bool m_triggerPacketSeen_ingress;
    uint32_t m_currentPostPacketHistoryCnt_ingress;
    size_t m_bufferedBytes_ingress;
    
    bool m_triggerPacketSeen_egress;
    uint32_t m_currentPostPacketHistoryCnt_egress;
    size_t m_bufferedBytes_egress;
    
    /// Max bytes per stream before forcing a flush
    const size_t m_flushThresholdBytes;
    
    /// The timeout duration for this specific stream.
    std::chrono::seconds m_myTimeout;
    
    // --- Statistics ---
    std::atomic<uint64_t> m_totalPacketsReceived{0};
    std::atomic<uint64_t> m_totalBytesReceived{0};
    std::atomic<uint64_t> m_totalPacketsSaved{0};
    
    /// Holds inter-packet arrival times (in microseconds)
    std::vector<uint64_t> m_interPacketGaps;
    /// Protects m_interPacketGaps from concurrent access
    mutable std::mutex m_gapVectorMutex;
    /// Timestamp of the previously seen packet
    timeval m_lastPacketTimestamp;

    /// Latency histogram buckets (us)
    const std::vector<uint64_t> m_latencyBuckets = 
        { 10, 50, 100, 250, 500, 1000, 5000, 10000, 50000, 100000 };
    
    /// Map of bucket (us) to packet count
    mutable std::map<uint64_t, uint64_t> m_latencyHistogram;
};

} // namespace pcapabvparser
#endif // __PACKET_STREAM_EVAL_H__
