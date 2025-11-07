/**
 * @file Consumer.cpp
 * @brief Implementation of the consumer thread's main logic.
 */

/*
 * Author: James Mathewson
 * Date: 6 November 2025
 * Version: 0.7 beta 
 */


#include "consumer.h"
#include "Globals.h"
#include "Logger.h"
#include "Benchmark.h"
#include "pcapparser.h"
#include "pcapkey.h"
#include "PacketStreamEval.h"
#include "pcap_abbv_cli_parser.h"
#include "PluggableMap.h"

#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <chrono>
#include <thread> // <-- FIX: Added this include

namespace pcapabvparser {

/// Type alias for the map of packet streams, using the pluggable map.
using PacketStreamMap = PluggableUnorderedMap<std::vector<uint8_t>, 
                                            std::shared_ptr<PacketStreamEval>, 
                                            VectorHash>;

// --- NEW: Timeout tracking maps ---
using TimePoint = std::chrono::steady_clock::time_point;
using ExpiryMap = std::map<TimePoint, std::vector<uint8_t>>;
using StreamExpiryLookupMap = PluggableUnorderedMap<std::vector<uint8_t>, TimePoint, VectorHash>;

/**
 * @brief Checks for and removes expired streams.
 * @param now The current time.
 * @param expiryMap The time-ordered map of expiries.
 * @param streamMap The main map of packet streams.
 * @param lookupMap The map for finding old expiry times.
 */
void check_for_expired_streams(
    TimePoint now,
    ExpiryMap& expiryMap,
    PacketStreamMap& streamMap,
    StreamExpiryLookupMap& lookupMap)
{
    // This is fast: std::map is sorted by time, so we only check the front.
    for (auto it = expiryMap.begin(); it != expiryMap.end(); /* no increment */) {
        if (it->first > now) {
            // This stream hasn't expired yet, so nothing after it has either.
            break; // O(1) in the common case
        }

        // --- This stream is expired ---
        const std::vector<uint8_t>& key = it->second;
        Logger::log("Stream " + print_simplekey(key) + " has expired. Cleaning up.");

        auto stream_it = streamMap.find(key);
        if (stream_it != streamMap.end()) {
            // --- MODIFIED: Call cleanup function ---
            stream_it->second->cleanupOnExpiry();
            streamMap.erase(stream_it);
        }
        
        lookupMap.erase(key);
        it = expiryMap.erase(it); // Erase and advance iterator
    }
}


void consumer_pcap_process_thread(
    size_t id,
    std::shared_ptr<IQueue<std::unique_ptr<pktBufferData_t>>> buffer,
    const std::string& tagFilter,
    const std::string& saveFilter,
    const TimeoutMap& timeoutMap)
{
    Logger::log(id, "Consumer thread started.");

    // --- Thread-Local Setup ---
    
    // --- NEW: Parse both "Tag" and "Save" ASTs ---
    pcapabvparser::FnParser tagParser(tagFilter);
    auto tag_ast = tagParser.parse();
    if (!tag_ast) {
        Logger::log(id, "ERROR: Failed to parse TAG filter string. Thread exiting.");
        return;
    }
    
    std::unique_ptr<ASTNode> save_ast;
    if (saveFilter == tagFilter) {
        // Optimization: if strings are identical, just re-use the tag_ast pointer.
        // PacketStreamEval will see the pointers are identical and won't clone twice.
        save_ast.reset(tag_ast.get());
    } else {
        pcapabvparser::FnParser saveParser(saveFilter);
        save_ast = saveParser.parse();
        if (!save_ast) {
            Logger::log(id, "ERROR: Failed to parse SAVE filter string. Thread exiting.");
            return;
        }
    }
    // ---

    PacketStreamMap packetStreamMap;
    
    // --- NEW: Timeout state ---
    ExpiryMap expiryMap;
    StreamExpiryLookupMap streamExpiryLookupMap;
    TimePoint lastExpiryCheckTime = std::chrono::steady_clock::now();
    // ---

    // --- Main Loop ---
    while (!g_done.load(std::memory_order_relaxed)) {
        auto opt = buffer->pop();
        if (!opt) {
            if (g_done.load(std::memory_order_acquire)) {
                break; // Exit signal received
            }
            
            // --- NEW: Check for expiry *only* when idle ---
            TimePoint now = std::chrono::steady_clock::now();
            if (now > lastExpiryCheckTime + std::chrono::seconds(1)) {
                check_for_expired_streams(now, expiryMap, packetStreamMap, streamExpiryLookupMap);
                lastExpiryCheckTime = now;
            }
            // ---
            
            std::this_thread::yield();
            continue;
        }
        
        // Start benchmark timer for this packet
        ScopedTimer timer; 
        
        auto pktData = std::move(opt.value());
        const auto& key = *(pktData->key);
        TimePoint now = std::chrono::steady_clock::now();

        std::shared_ptr<PacketStreamEval> packetInfo;
        auto find_iter = packetStreamMap.find(key);

        if (find_iter == packetStreamMap.end()) {
            packetInfo = std::make_shared<PacketStreamEval>();
            packetInfo->setId(print_simplekey(key));
            
            // --- MODIFIED: Call the new bind function ---
            // This clones the AST and links all functions
            packetInfo->registerAndBindAST(tag_ast.get(), save_ast.get(), timeoutMap);
            
            packetStreamMap[key] = packetInfo;
        } else {
            packetInfo = find_iter->second;
            
            // --- NEW: Remove old expiry entry ---
            auto old_expiry_it = streamExpiryLookupMap.find(key);
            if (old_expiry_it != streamExpiryLookupMap.end()) {
                expiryMap.erase(old_expiry_it->second);
            }
        }
        
        // --- NEW: Add/Update expiry ---
        std::chrono::seconds timeout = packetInfo->getTimeout();
        TimePoint newExpiryTime = now + timeout;
        expiryMap[newExpiryTime] = key;
        streamExpiryLookupMap[key] = newExpiryTime;
        // ---

        // --- Process the Packet ---
        bool isIngress = pktData->protoOffset->originalAddrPortOrdering; // <-- Get direction

        packetInfo->evaluatePacket(
            pktData->pktHeader.get(),
            pktData->pkt.get(),
            pktData->protoOffset.get(),
            pktData->protoStack.get() // <-- Pass the stack
        );

        packetInfo->transferPacket(
            std::move(pktData->pktHeader), 
            std::move(pktData->pkt),
            isIngress // <-- Pass direction
        );
        // ScopedTimer destructor runs here, adding to benchmark totals
    }

    // --- Shutdown Logic ---
    Logger::log(id, "Consumer thread shutting down. Cleaning up all streams...");
    for (auto& pair : packetStreamMap) {
        // --- MODIFIED: Call cleanup function ---
        pair.second->cleanupOnExpiry();
    }
    
    // Log benchmark results if enabled
    Logger::log(GetBenchmarkResults(id));

    Logger::log(id, "Consumer thread finished.");
}

} // namespace pcapabvparser
