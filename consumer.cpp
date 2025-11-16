/**
 * @file consumer.cpp
 * @author James Mathewson
 * @version 1.4.1 (Cleaned: Removed Checksum)
 * @brief Consumer implementation without checksum overhead.
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

// #define DEBUG_CONSUMER
#ifdef DEBUG_CONSUMER
    #define LOG_DEBUG(id, msg) Logger::log(id, "[DEBUG] " + std::string(msg))
#else
    #define LOG_DEBUG(id, msg) do {} while(0)
#endif

namespace pcapabvparser {

using PacketStreamMap = PluggableUnorderedMap<std::vector<uint8_t>, std::shared_ptr<PacketStreamEval>, hashFn>;
using StreamExpiryLookupMap = PluggableUnorderedMap<std::vector<uint8_t>, std::chrono::steady_clock::time_point, hashFn>;
using TimePoint = std::chrono::steady_clock::time_point;
using ExpiryMap = std::map<TimePoint, std::vector<uint8_t>>;

void check_for_expired_streams(TimePoint now, ExpiryMap& expiryMap, PacketStreamMap& streamMap, StreamExpiryLookupMap& lookupMap) {
    for (auto it = expiryMap.begin(); it != expiryMap.end(); ) {
        if (it->first > now) break;
        const std::vector<uint8_t>& key = it->second;
        auto stream_it = streamMap.find(key);
        if (stream_it != streamMap.end()) {
            stream_it->second->cleanupOnExpiry();
            streamMap.erase(stream_it);
            g_current_active_streams.fetch_sub(1, std::memory_order_relaxed);
        }
        lookupMap.erase(key);
        it = expiryMap.erase(it);
    }
}

void consumer_pcap_process_thread(size_t id, std::shared_ptr<IQueue<std::unique_ptr<pktBufferData_t>>> buffer, const std::string& tagFilter, const std::string& saveFilter, const TimeoutMap& timeoutMap) {
    Logger::log(id, "Consumer thread started.");

    try {
        pcapabvparser::FnParser tagParser(tagFilter);
        auto tag_ast = tagParser.parse();
        if (!tag_ast) { Logger::log(id, "ERROR: Failed to parse TAG filter string."); return; }

        std::unique_ptr<ASTNode> save_ast;
        if (saveFilter == tagFilter) {
            pcapabvparser::FnParser saveParser(saveFilter);
            save_ast = saveParser.parse();
        } else {
            pcapabvparser::FnParser saveParser(saveFilter);
            save_ast = saveParser.parse();
            if (!save_ast) { Logger::log(id, "ERROR: Failed to parse SAVE filter string."); return; }
        }

        PacketStreamMap packetStreamMap;
        ExpiryMap expiryMap;
        StreamExpiryLookupMap streamExpiryLookupMap;
        TimePoint lastExpiryCheckTime = std::chrono::steady_clock::now();

        while (true) {
            auto opt = buffer->pop();
            if (!opt) {
                if (g_done.load(std::memory_order_acquire)) break;
                TimePoint now = std::chrono::steady_clock::now();
                if (now > lastExpiryCheckTime + std::chrono::seconds(1)) {
                    check_for_expired_streams(now, expiryMap, packetStreamMap, streamExpiryLookupMap);
                    lastExpiryCheckTime = now;
                }
                std::this_thread::yield();
                continue;
            }

            auto pktData = std::move(opt.value());
            const auto& key = *(pktData->key);
            TimePoint now = std::chrono::steady_clock::now();
            std::shared_ptr<PacketStreamEval> packetInfo;
            auto find_iter = packetStreamMap.find(key);

            if (find_iter == packetStreamMap.end()) {
                packetInfo = std::make_shared<PacketStreamEval>(id);
                packetInfo->setId(print_simplekey(key));
                packetInfo->registerAndBindAST(tag_ast.get(), save_ast.get(), timeoutMap);
                packetStreamMap[key] = packetInfo;
                g_total_streams_created.fetch_add(1, std::memory_order_relaxed);
                int64_t current = g_current_active_streams.fetch_add(1, std::memory_order_relaxed) + 1;
                uint64_t max = g_max_active_streams.load(std::memory_order_relaxed);
                if ((uint64_t)current > max) g_max_active_streams.store((uint64_t)current, std::memory_order_relaxed);
            } else {
                packetInfo = find_iter->second;
                auto old_expiry_it = streamExpiryLookupMap.find(key);
                if (old_expiry_it != streamExpiryLookupMap.end()) expiryMap.erase(old_expiry_it->second);
            }

            std::chrono::seconds timeout = packetInfo->getTimeout();
            TimePoint newExpiryTime = now + timeout;
            expiryMap[newExpiryTime] = key;
            streamExpiryLookupMap[key] = newExpiryTime;

            bool isIngress = pktData->protoOffset->originalAddrPortOrdering;

            packetInfo->evaluatePacket(pktData->pktHeader.get(), pktData->pkt.get(), pktData->protoOffset.get(), pktData->protoStack.get());
            packetInfo->transferPacket(std::move(pktData->pktHeader), std::move(pktData->pkt), isIngress);
        }
        Logger::log(id, "Consumer thread shutting down. Cleaning up " + std::to_string(packetStreamMap.size()) + " streams...");
        for (auto& pair : packetStreamMap) pair.second->cleanupOnExpiry();
        Logger::log(id, "Consumer thread finished successfully.");

    } catch (const std::exception& e) { Logger::log(id, "FATAL ERROR: Uncaught exception: " + std::string(e.what())); } catch (...) { Logger::log(id, "FATAL ERROR: Unknown exception!"); }
}
}

