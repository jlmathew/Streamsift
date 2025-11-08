/**
 * @file consumer.cpp
 * @author James Mathewson
 * @version 0.9.13 beta
 * @brief Implementation of the consumer thread's main logic.
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
#include <thread>

namespace pcapabvparser {

/// Type alias for the map of packet streams, using the pluggable map.
using PacketStreamMap = PluggableUnorderedMap<std::vector<uint8_t>,
                                            std::shared_ptr<PacketStreamEval>,
                                            VectorHash>;

using TimePoint = std::chrono::steady_clock::time_point;
using ExpiryMap = std::map<TimePoint, std::vector<uint8_t>>;
using StreamExpiryLookupMap = PluggableUnorderedMap<std::vector<uint8_t>, TimePoint, VectorHash>;

/**
 * @brief Checks for and removes expired streams.
 * Uses a time-ordered map for O(1) checking of the oldest stream.
 */
void check_for_expired_streams(
    TimePoint now,
    ExpiryMap& expiryMap,
    PacketStreamMap& streamMap,
    StreamExpiryLookupMap& lookupMap)
{
    for (auto it = expiryMap.begin(); it != expiryMap.end(); /* no increment */) {
        if (it->first > now) {
            // The map is sorted by time. If the oldest hasn't expired, nothing has.
            break;
        }

        const std::vector<uint8_t>& key = it->second;
        // Logger::log("Stream " + print_simplekey(key) + " has expired. Cleaning up.");

        auto stream_it = streamMap.find(key);
        if (stream_it != streamMap.end()) {
            // Flush final packets and delete file if save filter wasn't met
            stream_it->second->cleanupOnExpiry();
            streamMap.erase(stream_it);
        }
       
        lookupMap.erase(key);
        it = expiryMap.erase(it); // Erase and advance iterator
    }
}

/**
 * @brief Main loop for a consumer thread.
 */
void consumer_pcap_process_thread(
    size_t id,
    std::shared_ptr<IQueue<std::unique_ptr<pktBufferData_t>>> buffer,
    const std::string& tagFilter,
    const std::string& saveFilter,
    const TimeoutMap& timeoutMap)
{
    Logger::log(id, "Consumer thread started.");

    try {
        // --- 1. Thread-Local AST Setup ---
        pcapabvparser::FnParser tagParser(tagFilter);
        auto tag_ast = tagParser.parse();
        if (!tag_ast) {
            Logger::log(id, "ERROR: Failed to parse TAG filter string. Thread exiting.");
            return;
        }
       
        std::unique_ptr<ASTNode> save_ast;
        if (saveFilter == tagFilter) {
            // Optimization: if identical, re-parse to get a fresh unique_ptr for the same logic
            pcapabvparser::FnParser saveParser(saveFilter);
            save_ast = saveParser.parse();
        } else {
            pcapabvparser::FnParser saveParser(saveFilter);
            save_ast = saveParser.parse();
            if (!save_ast) {
                Logger::log(id, "ERROR: Failed to parse SAVE filter string. Thread exiting.");
                return;
            }
        }

        // --- 2. Thread-Local State ---
        PacketStreamMap packetStreamMap;
        ExpiryMap expiryMap;
        StreamExpiryLookupMap streamExpiryLookupMap;
        TimePoint lastExpiryCheckTime = std::chrono::steady_clock::now();

        // --- 3. Main Processing Loop ---
        // FIX: Changed from 'while (!g_done)' to 'while (true)' to ensure draining.
        while (true) {
            auto opt = buffer->pop();
            if (!opt) {
                // Queue is empty. NOW we check if we should stop.
                if (g_done.load(std::memory_order_acquire)) {
                    break;
                }
               
                // While idle, perform maintenance (check for timeouts)
                TimePoint now = std::chrono::steady_clock::now();
                if (now > lastExpiryCheckTime + std::chrono::seconds(1)) {
                    check_for_expired_streams(now, expiryMap, packetStreamMap, streamExpiryLookupMap);
                    lastExpiryCheckTime = now;
                }
               
                std::this_thread::yield(); // Don't burn 100% CPU while idle
                continue;
            }
           
            // We have a packet!
            ScopedTimer timer;
            auto pktData = std::move(opt.value());
            const auto& key = *(pktData->key);
            TimePoint now = std::chrono::steady_clock::now();

            // Find or create the stream
            std::shared_ptr<PacketStreamEval> packetInfo;
            auto find_iter = packetStreamMap.find(key);

            if (find_iter == packetStreamMap.end()) {
                // New stream found
                packetInfo = std::make_shared<PacketStreamEval>();
                packetInfo->setId(print_simplekey(key));
                // Bind the ASTs to this specific stream's state
                packetInfo->registerAndBindAST(tag_ast.get(), save_ast.get(), timeoutMap);
               
                packetStreamMap[key] = packetInfo;
                g_total_streams_created.fetch_add(1, std::memory_order_relaxed);
            } else {
                // Existing stream found
                packetInfo = find_iter->second;
                // Remove old expiry time so we can update it
                auto old_expiry_it = streamExpiryLookupMap.find(key);
                if (old_expiry_it != streamExpiryLookupMap.end()) {
                    expiryMap.erase(old_expiry_it->second);
                }
            }
           
            // Update timeout
            std::chrono::seconds timeout = packetInfo->getTimeout();
            TimePoint newExpiryTime = now + timeout;
            expiryMap[newExpiryTime] = key;
            streamExpiryLookupMap[key] = newExpiryTime;

            // Process the packet
            bool isIngress = pktData->protoOffset->originalAddrPortOrdering;

            packetInfo->evaluatePacket(
                pktData->pktHeader.get(),
                pktData->pkt.get(),
                pktData->protoOffset.get(),
                pktData->protoStack.get()
            );

            packetInfo->transferPacket(
                std::move(pktData->pktHeader),
                std::move(pktData->pkt),
                isIngress
            );
        }

        // --- 4. Shutdown & Cleanup ---
        Logger::log(id, "Consumer thread shutting down. Cleaning up " + std::to_string(packetStreamMap.size()) + " streams...");
        for (auto& pair : packetStreamMap) {
            pair.second->cleanupOnExpiry();
        }
       
        // Logger::log(GetBenchmarkResults(id)); // Use macro if desired
        Logger::log(id, "Consumer thread finished successfully.");

    } catch (const std::exception& e) {
        Logger::log(id, "FATAL ERROR: Uncaught exception in consumer thread: " + std::string(e.what()));
    } catch (...) {
        Logger::log(id, "FATAL ERROR: Unknown exception in consumer thread!");
    }
}

} // namespace pcapabvparser
