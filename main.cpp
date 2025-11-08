/**
 * @file main.cpp
 * @author James Mathewson
 * @version 0.9.13 beta
 * @brief Main entry point for the pcap parser application.
 */

#include <iostream>
#include <chrono>
#include <pcap/pcap.h>
#include <csignal>
#include <vector>
#include <thread>
#include <algorithm>

#include "pcapparser.h"
#include "pcap_abbv_cli_parser.h"
#include "nonblockingbuffers.h"
#include "pcapkey.h"
#include "consumer.h"
#include "Globals.h"
#include "Logger.h"
#include "PacketStreamEval.h"
#include "Benchmark.h"
#include "ConfigParser.h"

// --- Debug Macro ---
// #define DEBUG_MAIN

#ifdef DEBUG_MAIN
    #define LOG_DEBUG(msg) Logger::log("[DEBUG][MAIN] " + std::string(msg))
#else
    #define LOG_DEBUG(msg) do {} while(0)
#endif

using namespace pcapabvparser;

// --- Global Variable Definitions ---
std::atomic<bool> g_done{false};
std::atomic<uint64_t> g_total_packets_read{0};
std::atomic<uint64_t> g_total_packets_dropped{0};
std::atomic<uint64_t> g_total_streams_created{0};
std::atomic<uint64_t> g_total_streams_saved{0};

void signalHandler(int signum) {
    Logger::log("Signal (" + std::to_string(signum) + ") received. Shutting down...");
    g_done.store(true, std::memory_order_release);
}

pcap_t* openPcapSource(char* errbuf) {
    pcap_t* pcapInputStream = nullptr;
    if (globalOptions.inputFile.empty()) {
        std::string iface = globalOptions.interfaceName.empty() ? "any" : globalOptions.interfaceName;
        Logger::log("Opening live capture on '" + iface + "' with snaplen "
                  + std::to_string(globalOptions.snapshotLength));
        pcapInputStream = pcap_open_live(iface.c_str(), globalOptions.snapshotLength, 1, 1000, errbuf);
    } else {
        Logger::log("Opening pcap file: " + globalOptions.inputFile);
        pcapInputStream = pcap_open_offline(globalOptions.inputFile.c_str(), errbuf);
    }
    if (pcapInputStream == nullptr) return nullptr;
   
    if (globalOptions.inputFile.empty()) {
         if (pcap_setnonblock(pcapInputStream, 1, errbuf) == -1) {
             Logger::log("Warning: Could not set non-blocking mode.");
         }
    }
    return pcapInputStream;
}

std::string resolveAlias(const std::string& filterOrAlias, const AliasMap& aliasMap) {
    if (filterOrAlias.empty()) return "";
    if (filterOrAlias.find_first_of("\"'() ") != std::string::npos) return filterOrAlias;
    auto it = aliasMap.find(filterOrAlias);
    if (it != aliasMap.end()) {
        Logger::log("Resolved filter alias '" + filterOrAlias + "' to: " + it->second);
        return it->second;
    }
    Logger::log("Warning: Filter '" + filterOrAlias + "' is not an alias and not quoted. Using as-is.");
    return filterOrAlias;
}

void runMultiThreaded(pcap_t* pcapInputStream, int layer2Proto,
                      const std::string& tagFilter, const std::string& saveFilter,
                      const TimeoutMap& timeoutMap) {
    Logger::log("Starting in Multi-Threaded mode with "
              + std::to_string(globalOptions.numConsumerThreads) + " threads.");

    const size_t BUFFER_SIZE = 65536;
    const size_t numConsumers = globalOptions.numConsumerThreads;

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

    struct pcap_pkthdr* pktHeader;
    const u_char* packetData;
    int resultTimeout = 0;

    while (!g_done.load(std::memory_order_acquire)) {
        resultTimeout = pcap_next_ex(pcapInputStream, &pktHeader, &packetData);
        if (g_done.load(std::memory_order_acquire)) break;
       
        if (resultTimeout == 0) {
             std::this_thread::yield();
             continue;
        }
        if (resultTimeout < 0) {
            if (resultTimeout == -2) Logger::log("Pcap file finished.");
            else Logger::log("Pcap error: " + std::string(pcap_geterr(pcapInputStream)));
            break;
        }

        g_total_packets_read.fetch_add(1, std::memory_order_relaxed);

        size_t bytesToParse = std::min((size_t)pktHeader->caplen, (size_t)globalOptions.snapshotLength);
        auto [key, offsets, stack] = parse_packet(layer2Proto, packetData, bytesToParse, globalOptions.tlsPorts);
       
        if (key->size() == 0) { continue; }

        auto headerCopy = std::make_unique<pcap_pkthdr>(*pktHeader);
        headerCopy->caplen = bytesToParse;
        auto packetCopy = std::unique_ptr<uint8_t[]>(new uint8_t[bytesToParse]);
        std::memcpy(packetCopy.get(), packetData, bytesToParse);
       
        VectorHash hasher;
        size_t target = hasher(*key) % numConsumers;
       
        auto queueData = std::make_unique<pktBufferData_t>(
            std::move(headerCopy), std::move(packetCopy),
            std::move(offsets), std::move(key), std::move(stack), target);

        if (!nb_buffers[target]->push(std::move(queueData))) {
            g_total_packets_dropped.fetch_add(1, std::memory_order_relaxed);
            static int drop_counter = 0;
            if (++drop_counter % 10000 == 0) {
                 Logger::log("Packet DROP! Consumer queue " + std::to_string(target) + " full. (x10000)");
            }
        }
    }

    Logger::log("Main loop finished. Signaling all threads to exit...");
    g_done.store(true, std::memory_order_release);
    for (auto& t : packetDataProcessors) { t.join(); }
}


void runSingleThreaded(pcap_t* pcapInputStream, int layer2Proto,
                       const std::string& tagFilter, const std::string& saveFilter,
                       const TimeoutMap& timeoutMap) {
    Logger::log("Starting in Single-Threaded mode.");
    pcapabvparser::FnParser tagParser(tagFilter);
    auto tag_ast = tagParser.parse();
    if (!tag_ast) return;
   
    std::unique_ptr<ASTNode> save_ast;
    if (saveFilter == tagFilter) save_ast.reset(tag_ast.get());
    else {
        pcapabvparser::FnParser saveParser(saveFilter);
        save_ast = saveParser.parse();
        if (!save_ast) return;
    }
   
    using PacketStreamMap = PluggableUnorderedMap<std::vector<uint8_t>, std::shared_ptr<PacketStreamEval>, VectorHash>;
    PacketStreamMap packetStreamMap;
    using TimePoint = std::chrono::steady_clock::time_point;
    using ExpiryMap = std::map<TimePoint, std::vector<uint8_t>>;
    using StreamExpiryLookupMap = PluggableUnorderedMap<std::vector<uint8_t>, TimePoint, VectorHash>;
   
    ExpiryMap expiryMap;
    StreamExpiryLookupMap streamExpiryLookupMap;
    TimePoint lastExpiryCheckTime = std::chrono::steady_clock::now();

    struct pcap_pkthdr* pktHeader;
    const u_char* packetData;
    int resultTimeout = 0;

    while (!g_done.load(std::memory_order_acquire)) {
        resultTimeout = pcap_next_ex(pcapInputStream, &pktHeader, &packetData);
        if (g_done.load(std::memory_order_acquire)) break;

        TimePoint now = std::chrono::steady_clock::now();
        if (resultTimeout == 0) {
            if (now > lastExpiryCheckTime + std::chrono::seconds(1)) {
                 for (auto it = expiryMap.begin(); it != expiryMap.end(); ) {
                    if (it->first > now) break;
                    auto stream_it = packetStreamMap.find(it->second);
                    if (stream_it != packetStreamMap.end()) {
                        LOG_DEBUG("Stream expired: " + print_simplekey(it->second));
                        stream_it->second->cleanupOnExpiry();
                        packetStreamMap.erase(stream_it);
                    }
                    streamExpiryLookupMap.erase(it->second);
                    it = expiryMap.erase(it);
                 }
                lastExpiryCheckTime = now;
            }
            continue;
        }
        if (resultTimeout < 0) {
             if (resultTimeout == -2) Logger::log("Pcap file finished.");
             else Logger::log("Pcap error: " + std::string(pcap_geterr(pcapInputStream)));
             break;
        }

        g_total_packets_read.fetch_add(1, std::memory_order_relaxed);

        ScopedTimer timer;
        size_t bytesToParse = std::min((size_t)pktHeader->caplen, (size_t)globalOptions.snapshotLength);
        auto [key_ptr, offsets, stack] = parse_packet(layer2Proto, packetData, bytesToParse, globalOptions.tlsPorts);
        if (key_ptr->size() == 0) continue;
        const auto& key = *key_ptr;

        std::shared_ptr<PacketStreamEval> packetInfo;
        auto find_iter = packetStreamMap.find(key);

        if (find_iter == packetStreamMap.end()) {
            packetInfo = std::make_shared<PacketStreamEval>();
            packetInfo->setId(print_simplekey(key));
            packetInfo->registerAndBindAST(tag_ast.get(), (saveFilter == tagFilter ? tag_ast.get() : save_ast.get()), timeoutMap);
            packetStreamMap[key] = packetInfo;
            g_total_streams_created.fetch_add(1, std::memory_order_relaxed);
        } else {
            packetInfo = find_iter->second;
            auto old_expiry_it = streamExpiryLookupMap.find(key);
            if (old_expiry_it != streamExpiryLookupMap.end()) {
                expiryMap.erase(old_expiry_it->second);
            }
        }
       
        std::chrono::seconds timeout = packetInfo->getTimeout();
        TimePoint newExpiryTime = now + timeout;
        expiryMap[newExpiryTime] = key;
        streamExpiryLookupMap[key] = newExpiryTime;

        auto headerCopy = std::make_unique<pcap_pkthdr>(*pktHeader);
        headerCopy->caplen = bytesToParse;
        auto packetCopy = std::unique_ptr<uint8_t[]>(new uint8_t[bytesToParse]);
        std::memcpy(packetCopy.get(), packetData, bytesToParse);

        packetInfo->evaluatePacket(headerCopy.get(), packetCopy.get(), offsets.get(), stack.get());
        packetInfo->transferPacket(std::move(headerCopy), std::move(packetCopy), offsets->originalAddrPortOrdering);
    }

    for (auto& pair : packetStreamMap) {
        pair.second->cleanupOnExpiry();
    }
   
    packetStreamMap.clear();
    expiryMap.clear();
    streamExpiryLookupMap.clear();
   
    Logger::log(GetBenchmarkResults(0));
}

int main(int argc, char* argv[]) {
    g_done.store(false);
    g_total_packets_read.store(0);
    g_total_packets_dropped.store(0);
    g_total_streams_created.store(0);
    g_total_streams_saved.store(0);

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
   
    pcapabvparser::cli_parser parseCliOptions(argc, argv);
    TimeoutMap timeoutMap = ConfigParser::parseTimeouts(globalOptions.protocolTimeoutConfigFileName);
    AliasMap aliasMap = ConfigParser::parseAliasFile(globalOptions.filterAliasFile);
    std::string tagFilter = resolveAlias(globalOptions.pcapPacketOfInterestFilter, aliasMap);
    std::string saveFilter = resolveAlias(globalOptions.pcapPacketTriggerToSaveFilter, aliasMap);

    if (tagFilter.empty()) { Logger::log("Error: No 'Tag' filter provided (`-t`). Exiting."); return 1; }
    if (saveFilter.empty()) { Logger::log("Info: No 'Save' filter provided. Defaulting to 'Tag'."); saveFilter = tagFilter; }
   
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcapInputStream = openPcapSource(errbuf);
    if (pcapInputStream == nullptr) { Logger::log("Pcap open error: " + std::string(errbuf)); return 1; }
    int layer2Proto = pcap_datalink(pcapInputStream);
   
    auto start_time = std::chrono::high_resolution_clock::now();

    try {
        if (globalOptions.numConsumerThreads == 0) {
            runSingleThreaded(pcapInputStream, layer2Proto, tagFilter, saveFilter, timeoutMap);
        } else {
            runMultiThreaded(pcapInputStream, layer2Proto, tagFilter, saveFilter, timeoutMap);
        }
    } catch (const std::exception& e) {
        Logger::log("FATAL ERROR in main thread: " + std::string(e.what()));
    } catch (...) {
        Logger::log("FATAL ERROR: Unknown exception in main thread.");
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

    pcap_close(pcapInputStream);

    std::cout << "\n=== StreamSift Execution Summary ===\n"
              << "  Execution Time: " << (duration_ms / 1000.0) << " seconds\n"
              << "  Total Packets Read:    " << g_total_packets_read.load() << "\n"
              << "  Total Packets Dropped: " << g_total_packets_dropped.load()
              << " (" << (g_total_packets_read > 0 ? (double)g_total_packets_dropped * 100.0 / g_total_packets_read : 0.0) << "%)\n"
              << "  Total Streams Created: " << g_total_streams_created.load() << "\n"
              << "  Total Streams Saved:   " << g_total_streams_saved.load() << "\n"
              << "====================================\n" << std::endl;

    return 0;
}


