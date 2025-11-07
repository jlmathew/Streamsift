/**
 * @file main.cpp
 * @brief Main entry point for the pcap parser application.
 */

/*
 * Author: James Mathewson
 * Date: 6 November 2025
 * Version: 0.7 beta 
 */


#include <iostream>
#include <chrono>
#include <pcap/pcap.h>
#include <csignal> // For signal handling
#include <vector>
#include <thread>
#include <algorithm> // For std::min

#include "pcapparser.h"
#include "pcap_abbv_cli_parser.h"
#include "nonblockingbuffers.h"
#include "pcapkey.h"
#include "consumer.h"
#include "Globals.h"
#include "Logger.h"
#include "PacketStreamEval.h" // For single-threaded mode
#include "Benchmark.h"        // For single-threaded mode
#include "ConfigParser.h" // For AliasMap and TimeoutMap

using namespace pcapabvparser;

// --- Global Variable Definitions ---
std::atomic<bool> g_done{false};

/**
 * @brief Handles OS signals (SIGINT, SIGTERM) for graceful shutdown.
 * @param signum The signal number received.
 */
void signalHandler(int signum) {
    Logger::log("Signal (" + std::to_string(signum) + ") received. Shutting down...");
    g_done.store(true, std::memory_order_release);
}

/**
 * @brief Opens the pcap source (live interface or offline file).
 * @param errbuf Buffer for error messages.
 * @return A valid pcap_t* handle or nullptr on failure.
 */
pcap_t* openPcapSource(char* errbuf) {
    pcap_t* pcapInputStream = nullptr;

    if (globalOptions.inputFile.empty()) {
        // --- LIVE CAPTURE ---
        std::string iface = globalOptions.interfaceName.empty() ? "any" : globalOptions.interfaceName;
        Logger::log("Opening live capture on '" + iface + "' with snaplen " 
                  + std::to_string(globalOptions.snapshotLength));
        
        // 1 = promiscuous mode, 1000ms timeout
        pcapInputStream = pcap_open_live(iface.c_str(), 
                                         globalOptions.snapshotLength, // <-- Used here
                                         1, 
                                         1000, 
                                         errbuf);
    } else {
        // --- OFFLINE FILE ---
        Logger::log("Opening pcap file: " + globalOptions.inputFile);
        pcapInputStream = pcap_open_offline(globalOptions.inputFile.c_str(), errbuf);
    }

    if (pcapInputStream == nullptr) {
        return nullptr; // Error already in errbuf
    }

    // Set non-blocking mode on the handle
    if (pcap_setnonblock(pcapInputStream, 1, errbuf) == -1) {
        Logger::log("Warning: Could not set non-blocking mode.");
    }
    
    return pcapInputStream;
}


/**
 * @brief Resolves a filter string if it's an alias.
 * @param filterOrAlias The string from the CLI.
 * @param aliasMap The map of loaded aliases.
 * @return The resolved filter string.
 */
std::string resolveAlias(const std::string& filterOrAlias, const AliasMap& aliasMap) {
    if (filterOrAlias.empty()) {
        return "";
    }
    // Simple check: if it contains quotes or operators, it's not an alias
    if (filterOrAlias.find_first_of("\"'() ") != std::string::npos) {
        return filterOrAlias; // It's a full filter string, not an alias
    }
    
    // It's a simple name, look it up
    auto it = aliasMap.find(filterOrAlias);
    if (it != aliasMap.end()) {
        Logger::log("Resolved filter alias '" + filterOrAlias + "' to: " + it->second);
        return it->second; // Return the filter string
    }
    
    // Not an alias, but also not a quoted string.
    // This is probably a malformed filter, but we'll pass it to the parser.
    Logger::log("Warning: Filter '" + filterOrAlias + "' is not an alias and not quoted. Using as-is.");
    return filterOrAlias;
}


/**
 * @brief Main execution function for multi-threaded mode.
 * @param pcapInputStream The opened pcap handle.
 * @param layer2Proto The L2 protocol from pcap_datalink().
 * @param tagFilter The resolved "Tag" filter string.
 * @param saveFilter The resolved "Save" filter string.
 * @param timeoutMap The loaded protocol timeout map.
 */
void runMultiThreaded(pcap_t* pcapInputStream, int layer2Proto, 
                      const std::string& tagFilter, const std::string& saveFilter, 
                      const TimeoutMap& timeoutMap) {
    Logger::log("Starting in Multi-Threaded mode with " 
              + std::to_string(globalOptions.numConsumerThreads) + " threads.");

    const size_t BUFFER_SIZE = 256; // Or from CLI
    const size_t numConsumers = globalOptions.numConsumerThreads;

    // --- Setup Buffers and Threads ---
    std::vector<std::shared_ptr<IQueue<std::unique_ptr<pktBufferData_t>>>> nb_buffers;
    for (size_t i = 0; i < numConsumers; ++i) {
        nb_buffers.emplace_back(
            std::make_shared<NonBlockingCircularBuffer<std::unique_ptr<pktBufferData_t>, BUFFER_SIZE>>()
        );
    }

    std::atomic<bool> consumersReady{false};
    std::vector<std::thread> packetDataProcessors;
    for (size_t i = 0; i < numConsumers; ++i) {
        packetDataProcessors.emplace_back([i, &nb_buffers, &consumersReady, &tagFilter, &saveFilter, &timeoutMap]() {
            while (!consumersReady.load(std::memory_order_acquire)) { std::this_thread::yield(); }
            consumer_pcap_process_thread(i, nb_buffers[i], tagFilter, saveFilter, timeoutMap);
        });
    }
    consumersReady.store(true, std::memory_order_release);

    // --- Main Producer Loop ---
    struct pcap_pkthdr* pktHeader;
    const u_char* packetData;
    int resultTimeout = 0;

    while (!g_done.load(std::memory_order_acquire)) {
        resultTimeout = pcap_next_ex(pcapInputStream, &pktHeader, &packetData);
        
        if (g_done.load(std::memory_order_acquire)) break;
        
        if (resultTimeout == 0) { // Timeout (in non-blocking mode)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        if (resultTimeout < 0) {
            Logger::log("Pcap file finished or error.");
            break; // EOF or error
        }

        // --- Enforce CLI snapshot length ---
        size_t bytesToParse = std::min((size_t)pktHeader->caplen, 
                                       (size_t)globalOptions.snapshotLength);
        
        // --- Parse (using truncated length) ---
        auto [key, offsets, stack] = parse_packet(
            layer2Proto, 
            packetData, 
            bytesToParse,
            globalOptions.tlsPorts
        );
        
        if (key->size() == 0) { continue; } // Bad packet

        // --- Copy (only the truncated amount) ---
        auto headerCopy = std::make_unique<pcap_pkthdr>(*pktHeader);
        headerCopy->caplen = bytesToParse; // Store truncated length

        auto packetCopy = std::unique_ptr<uint8_t[]>(new uint8_t[bytesToParse]);
        std::memcpy(packetCopy.get(), packetData, bytesToParse);
        
        // --- Hash and Push ---
        VectorHash hasher;
        size_t target = hasher(*key) % numConsumers;
        
        auto queueData = std::make_unique<pktBufferData_t>(
            std::move(headerCopy), std::move(packetCopy), 
            std::move(offsets), std::move(key), std::move(stack), target);

        if (!nb_buffers[target]->push(std::move(queueData))) {
            Logger::log("Packet DROP! Consumer queue " + std::to_string(target) + " is full.");
        }
    }

    // --- Shutdown ---
    Logger::log("Main loop finished. Signaling all threads to exit...");
    g_done.store(true, std::memory_order_release);

    for (auto& t : packetDataProcessors) {
        t.join();
    }
}

/**
 * @brief Main execution function for single-threaded mode.
 * @param pcapInputStream The opened pcap handle.
 * @param layer2Proto The L2 protocol from pcap_datalink().
 * @param tagFilter The resolved "Tag" filter string.
 * @param saveFilter The resolved "Save" filter string.
 * @param timeoutMap The loaded protocol timeout map.
 */
void runSingleThreaded(pcap_t* pcapInputStream, int layer2Proto, 
                       const std::string& tagFilter, const std::string& saveFilter, 
                       const TimeoutMap& timeoutMap) {
    Logger::log("Starting in Single-Threaded mode.");
    
    // --- Setup (Done in main thread) ---
    pcapabvparser::FnParser tagParser(tagFilter);
    auto tag_ast = tagParser.parse();
    if (!tag_ast) {
        Logger::log("ERROR: Failed to parse TAG filter string. Exiting.");
        return;
    }
    
    std::unique_ptr<ASTNode> save_ast;
    if (saveFilter == tagFilter) {
        save_ast.reset(tag_ast.get());
    } else {
        pcapabvparser::FnParser saveParser(saveFilter);
        save_ast = saveParser.parse();
        if (!save_ast) {
            Logger::log("ERROR: Failed to parse SAVE filter string. Exiting.");
            return;
        }
    }
    
    using PacketStreamMap = PluggableUnorderedMap<std::vector<uint8_t>, 
                                                std::shared_ptr<PacketStreamEval>, 
                                                VectorHash>;
    PacketStreamMap packetStreamMap;
    
    // --- Timeout state for single-threaded mode ---
    using TimePoint = std::chrono::steady_clock::time_point;
    using ExpiryMap = std::map<TimePoint, std::vector<uint8_t>>;
    using StreamExpiryLookupMap = PluggableUnorderedMap<std::vector<uint8_t>, TimePoint, VectorHash>;
    
    ExpiryMap expiryMap;
    StreamExpiryLookupMap streamExpiryLookupMap; // <-- FIX: Declared this map
    TimePoint lastExpiryCheckTime = std::chrono::steady_clock::now();
    // ---

    // --- Main Processing Loop ---
    struct pcap_pkthdr* pktHeader;
    const u_char* packetData;
    int resultTimeout = 0;

    while (!g_done.load(std::memory_order_acquire)) {
        resultTimeout = pcap_next_ex(pcapInputStream, &pktHeader, &packetData);
        
        if (g_done.load(std::memory_order_acquire)) break;

        TimePoint now = std::chrono::steady_clock::now();
        if (resultTimeout == 0) { // Timeout
            // --- Check expiry on idle ---
            if (now > lastExpiryCheckTime + std::chrono::seconds(1)) {
                 for (auto it = expiryMap.begin(); it != expiryMap.end(); /*...*/) {
                    if (it->first > now) break;
                    auto stream_it = packetStreamMap.find(it->second);
                    if (stream_it != packetStreamMap.end()) {
                        stream_it->second->cleanupOnExpiry(); // <-- Call cleanup
                        packetStreamMap.erase(stream_it);
                    }
                    streamExpiryLookupMap.erase(it->second); // <-- FIX: Use the correct map
                    it = expiryMap.erase(it);
                 }
                lastExpiryCheckTime = now;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        if (resultTimeout < 0) {
            Logger::log("Pcap file finished or error.");
            break; // EOF or error
        }

        ScopedTimer timer;

        // --- Enforce CLI snapshot length ---
        size_t bytesToParse = std::min((size_t)pktHeader->caplen, 
                                       (size_t)globalOptions.snapshotLength);

        // --- Parse ---
        auto [key_ptr, offsets, stack] = parse_packet(
            layer2Proto,
            packetData,
            bytesToParse,
            globalOptions.tlsPorts
        );

        if (key_ptr->size() == 0) { continue; }
        const auto& key = *key_ptr;
        // ---

        // --- Find Stream / Update Expiry ---
        std::shared_ptr<PacketStreamEval> packetInfo;
        auto find_iter = packetStreamMap.find(key);

        if (find_iter == packetStreamMap.end()) {
            packetInfo = std::make_shared<PacketStreamEval>();
            packetInfo->setId(print_simplekey(key));
            packetInfo->registerAndBindAST(tag_ast.get(), save_ast.get(), timeoutMap);
            packetStreamMap[key] = packetInfo;
        } else {
            packetInfo = find_iter->second;
            // Remove old expiry entry
            auto old_expiry_it = streamExpiryLookupMap.find(key);
            if (old_expiry_it != streamExpiryLookupMap.end()) {
                expiryMap.erase(old_expiry_it->second);
            }
        }
        
        // Add/Update expiry
        std::chrono::seconds timeout = packetInfo->getTimeout(); // <-- FIX: This function now exists
        TimePoint newExpiryTime = now + timeout;
        expiryMap[newExpiryTime] = key;
        streamExpiryLookupMap[key] = newExpiryTime;
        // ---

        // --- Process ---
        auto headerCopy = std::make_unique<pcap_pkthdr>(*pktHeader);
        headerCopy->caplen = bytesToParse;
        auto packetCopy = std::unique_ptr<uint8_t[]>(new uint8_t[bytesToParse]);
        std::memcpy(packetCopy.get(), packetData, bytesToParse);

        packetInfo->evaluatePacket(
            headerCopy.get(),
            packetCopy.get(),
            offsets.get(),
            stack.get()
        );

        packetInfo->transferPacket(
            std::move(headerCopy), 
            std::move(packetCopy),
            offsets->originalAddrPortOrdering // Pass direction
        );
    }

    // --- Shutdown ---
    Logger::log("Main loop finished. Cleaning up all streams...");
    for (auto& pair : packetStreamMap) {
        pair.second->cleanupOnExpiry();
    }
    
    Logger::log(GetBenchmarkResults(0)); // "Thread 0"
}


/**
 * @brief Main entry point.
 */
int main(int argc, char* argv[]) {
    // --- Register Signal Handlers ---
    signal(SIGINT, signalHandler);  // Ctrl+C
    signal(SIGTERM, signalHandler); // `kill`
    
    // --- Parse CLI ---
    pcapabvparser::cli_parser parseCliOptions(argc, argv);
    
    // --- Parse Config Files ---
    TimeoutMap timeoutMap = ConfigParser::parseTimeouts(globalOptions.protocolTimeoutConfigFileName);
    AliasMap aliasMap = ConfigParser::parseAliasFile(globalOptions.filterAliasFile);
    
    // --- Resolve Filter Aliases ---
    std::string tagFilter = resolveAlias(globalOptions.pcapPacketOfInterestFilter, aliasMap);
    std::string saveFilter = resolveAlias(globalOptions.pcapPacketTriggerToSaveFilter, aliasMap);

    if (tagFilter.empty()) {
        Logger::log("Error: No 'Tag' filter provided (`-t`). Exiting.");
        return 1;
    }
    if (saveFilter.empty()) {
        Logger::log("Info: No 'Save' filter (`-p`) provided. Defaulting to 'Tag' filter for saving.");
        saveFilter = tagFilter;
    }
    
    // --- Check for unused options ---
    if (globalOptions.bufferSizePerTotalFlush != 30000000) { // Not default
        Logger::log("Warning: --bufferflushsize is parsed but not implemented.");
    }
    if (globalOptions.combinePacketsIntoPcap) {
        Logger::log("Warning: --singlepcap is parsed but not implemented.");
    }
    // ---

    // --- Open Pcap ---
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcapInputStream = openPcapSource(errbuf);
    if (pcapInputStream == nullptr) {
        Logger::log("Pcap open error: " + std::string(errbuf));
        return 1;
    }

    int layer2Proto = pcap_datalink(pcapInputStream);
    
    // --- Run Mode ---
    if (globalOptions.numConsumerThreads == 0) {
        runSingleThreaded(pcapInputStream, layer2Proto, tagFilter, saveFilter, timeoutMap);
    } else {
        runMultiThreaded(pcapInputStream, layer2Proto, tagFilter, saveFilter, timeoutMap);
    }

    // --- Cleanup ---
    Logger::log("All tasks finished. Exiting.");
    pcap_close(pcapInputStream);
    return 0;
}
