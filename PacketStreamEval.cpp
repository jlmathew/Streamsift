/**
 * @file PacketStreamEval.cpp
 * @brief Implementation of the PacketStreamEval class.
 */

/*
 * Author: James Mathewson
 * Date: 6 November 2025
 * Version: 0.7 beta 
 */


#include "PacketStreamEval.h"
#include "pcap_abbv_cli_parser.h" // For globalOptions
#include "Logger.h"
#include <iostream>
#include <iomanip> // For std::setw
#include <numeric> // For std::accumulate
#include <cstdio>  // For std::remove

namespace pcapabvparser {

// Constructor: Initialize from global options
PacketStreamEval::PacketStreamEval()
    : m_saveFilterIsSameAsTagFilter(false),
      m_saveFilterMatched(false),
      m_prePacketHistoryMax(globalOptions.bufferPacketsBefore),
      m_postPacketHistoryMax(globalOptions.bufferPacketsAfter),
      // --- Per-direction state init ---
      m_triggerPacketSeen_ingress(false),
      m_currentPostPacketHistoryCnt_ingress(0),
      m_bufferedBytes_ingress(0),
      m_triggerPacketSeen_egress(false),
      m_currentPostPacketHistoryCnt_egress(0),
      m_bufferedBytes_egress(0),
      // ---
      m_flushThresholdBytes(globalOptions.bufferSizePerStreamFlush),
      m_myTimeout(60) // Default timeout
{
    // Set the stream mode from global options
    m_streamMode = (globalOptions.streamMode == "separate") 
                   ? StreamMode::SEPARATE 
                   : StreamMode::COMBINED;

    m_lastPacketTimestamp = {0, 0};
    for(auto bucket : m_latencyBuckets) {
        m_latencyHistogram[bucket] = 0;
    }
}

// Destructor
PacketStreamEval::~PacketStreamEval() {
    // Summary is printed by cleanupOnExpiry(), which is called
    // by the consumer thread before this object is destroyed.
    Logger::log("Stream " + m_id + " destroyed.");
}

void PacketStreamEval::setId(const std::string& id) {
    m_id = id;
    // This is now a BASE name.
    // .pcap, _client.pcap, or _server.pcap will be added later.
    m_fileNameBase = globalOptions.preName + "_" + m_id;
}

/**
 * @brief Creates protocol triggers, clones the ASTs, binds them, and sets timeout.
 */
void PacketStreamEval::registerAndBindAST(const ASTNode* tagRoot, const ASTNode* saveRoot, const TimeoutMap& timeoutMap) {
    // --- 1. Create all protocol triggers ---
    m_protocolsUsed["IP"] = protoIpv4Trigger::create();
    m_protocolsUsed["TCP"] = protoTcpTrigger::create();
    m_protocolsUsed["UDP"] = protoUdpTrigger::create();
    m_protocolsUsed["ICMP"] = protoIcmpTrigger::create();
    m_protocolsUsed["GRE"] = protoGreTrigger::create();
    m_protocolsUsed["DNS"] = protoDnsTrigger::create();
    m_protocolsUsed["TLS"] = protoTlsTrigger::create();
    // ... add IPv6 etc. ...

    // --- 2. Clone and Bind TAG AST ---
    if (tagRoot) {
        // --- FIX: .reset() expects a raw pointer, use .release() ---
        m_boundTagAst.reset(tagRoot->clone().release());
    } else {
        Logger::log("Error: Cannot bind a null TAG AST.");
        return;
    }
    
    // --- 3. Clone and Bind SAVE AST ---
    if (saveRoot == tagRoot) {
        // Optimization: Save filter is same as tag filter
        m_saveFilterIsSameAsTagFilter = true;
        m_boundSaveAst = nullptr; // No need for a second copy
    } else if (saveRoot) {
        // --- FIX: .reset() expects a raw pointer, use .release() ---
        m_boundSaveAst.reset(saveRoot->clone().release());
    } else {
        Logger::log("Error: Cannot bind a null SAVE AST.");
        return;
    }

    // --- 4. Determine this stream's timeout ---
    determineTimeout(timeoutMap);
}

/**
 * @brief Recursive helper to walk the AST and bind functions.
 */
void PacketStreamEval::bindAstRecursive(ASTNode* node) {
    if (!node) return;

    if (auto* func = dynamic_cast<FuncCallNode*>(node)) {
        // This is a function. Find it and bind it.
        Func* func_ptr = nullptr;
        for (auto const& [name, trigger_ptr] : m_protocolsUsed) {
            func_ptr = trigger_ptr->findFunction(func->name);
            if (func_ptr) {
                break; // Found it
            }
        }

        if (func_ptr) {
            // Success! Store the pointer.
            func->m_bound_function_ptr = func_ptr;
        } else {
            // --- NEW: Handle missing function ---
            // Function not found. Bind a dummy "error" lambda.
            std::string func_name = func->name;
            std::string stream_id = m_id;
            
            // Create and store the error lambda so it has a stable address
            m_errorFuncs[func_name] = [func_name, stream_id](const std::vector<int>&) {
                Logger::log("Stream " + stream_id + ": Error: Function '" + func_name + "' not defined.");
                return 0; // Return default 0
            };
            
            // Bind the FuncCallNode to the error lambda we just stored
            func->m_bound_function_ptr = &m_errorFuncs[func_name];
        }

        // Recurse into arguments
        for (auto& arg : func->args) {
            bindAstRecursive(arg.get());
        }

    } else if (auto* unary = dynamic_cast<UnaryNode*>(node)) {
        // Recurse into operand
        bindAstRecursive(unary->operand.get());

    } else if (auto* binary = dynamic_cast<BinaryNode*>(node)) {
        // Recurse into both sides
        bindAstRecursive(binary->left.get());
        bindAstRecursive(binary->right.get());
    }
    // (ConstNode has no children, so no 'else' needed)
}


/**
 * @brief Evaluates a new packet against the pre-bound ASTs.
 */
void PacketStreamEval::evaluatePacket(pcap_pkthdr* hdr, uint8_t* data, PacketOffsets_t* offsets, const ProtocolStack_t* stack) {
    // --- Update Stats ---
    m_totalPacketsReceived++;
    m_totalBytesReceived += hdr->len;

    // Calculate inter-packet gap and update histogram
    if (m_lastPacketTimestamp.tv_sec != 0) {
        uint64_t current_ts_us = (uint64_t)hdr->ts.tv_sec * 1000000 + hdr->ts.tv_usec;
        uint64_t last_ts_us = (uint64_t)m_lastPacketTimestamp.tv_sec * 1000000 + m_lastPacketTimestamp.tv_usec;
        uint64_t gap = (current_ts_us > last_ts_us) ? (current_ts_us - last_ts_us) : 0;
        
        std::lock_guard<std::mutex> lock(m_gapVectorMutex);
        m_interPacketGaps.push_back(gap);
        
        // Find the correct bucket
        for (auto bucket : m_latencyBuckets) {
            if (gap <= bucket) {
                m_latencyHistogram[bucket]++;
                break;
            }
        }
    }
    m_lastPacketTimestamp = hdr->ts;

    // --- Set Packet Context ---
    for (auto const& [name, trigger_ptr] : m_protocolsUsed) {
        trigger_ptr->setCurrentPacket(offsets, data, stack);
    }

    // --- 1. Evaluate "Tag" Filter ---
    if (!m_boundTagAst) return;
    int tag_result = m_boundTagAst->eval();
    
    if (tag_result != 0) {
        bool isIngress = offsets->originalAddrPortOrdering;
        if (m_streamMode == StreamMode::COMBINED) {
            if (!m_triggerPacketSeen_ingress) {
                m_triggerPacketSeen_ingress = true;
                m_currentPostPacketHistoryCnt_ingress = m_postPacketHistoryMax;
            }
        } else { // SEPARATE mode
            if (isIngress) {
                if (!m_triggerPacketSeen_ingress) {
                    m_triggerPacketSeen_ingress = true;
                    m_currentPostPacketHistoryCnt_ingress = m_postPacketHistoryMax;
                }
            } else {
                if (!m_triggerPacketSeen_egress) {
                    m_triggerPacketSeen_egress = true;
                    m_currentPostPacketHistoryCnt_egress = m_postPacketHistoryMax;
                }
            }
        }
    }
    
    // --- 2. Evaluate "Save" Filter ---
    if (!m_saveFilterMatched) {
        if (m_saveFilterIsSameAsTagFilter) {
            if (tag_result != 0) {
                m_saveFilterMatched = true; // Tag match = Save match
            }
        } else if (m_boundSaveAst) { // Check if it's not null
            int save_result = m_boundSaveAst->eval();
            if (save_result != 0) {
                m_saveFilterMatched = true;
            }
        }
    }
}

/**
 * @brief Internal helper to manage buffering logic for one direction.
 */
void PacketStreamEval::transferPacketToBuffer(
    PacketBuffer& buffer,
    bool& triggerSeen,
    uint32_t& postPktCnt,
    size_t& bufferedBytes,
    std::unique_ptr<pcap_pkthdr>&& header, 
    std::unique_ptr<uint8_t[]>&& data
) {
    size_t packet_size = header->caplen;
    bufferedBytes += packet_size;

    if (!triggerSeen) {
        // STATE 1: Looking for a "Tag"
        buffer.emplace_back(std::move(header), std::move(data));
        while (buffer.size() > m_prePacketHistoryMax) {
            bufferedBytes -= buffer.front().first->caplen;
            buffer.pop_front(); 
        }
    } else {
        // STATE 2: "Tag" Seen, Saving 'Post' Packets
        if (postPktCnt > 0) {
            buffer.emplace_back(std::move(header), std::move(data));
            postPktCnt--;

            if (postPktCnt == 0) {
                // Last packet saved. Reset trigger.
                triggerSeen = false;
            }
        }
    }

    // Byte-based flush
    if (bufferedBytes > m_flushThresholdBytes) {
        Logger::log("Stream " + m_id + ": Reached flush threshold (" 
                  + std::to_string(bufferedBytes) + " bytes). Flushing.");
        flushPacketsToDisk();
    }
}

/**
 * @brief Main dispatcher for transferring packets.
 */
void PacketStreamEval::transferPacket(std::unique_ptr<pcap_pkthdr>&& header, std::unique_ptr<uint8_t[]>&& data, bool isIngress) {
    
    if (m_streamMode == StreamMode::COMBINED) {
        // Use ingress buffer for everything
        transferPacketToBuffer(
            m_packetHistory_ingress,
            m_triggerPacketSeen_ingress,
            m_currentPostPacketHistoryCnt_ingress,
            m_bufferedBytes_ingress,
            std::move(header),
            std::move(data)
        );
    } else {
        // SEPARATE mode
        if (isIngress) {
            transferPacketToBuffer(
                m_packetHistory_ingress,
                m_triggerPacketSeen_ingress,
                m_currentPostPacketHistoryCnt_ingress,
                m_bufferedBytes_ingress,
                std::move(header),
                std::move(data)
            );
        } else { // Egress
            transferPacketToBuffer(
                m_packetHistory_egress,
                m_triggerPacketSeen_egress,
                m_currentPostPacketHistoryCnt_egress,
                m_bufferedBytes_egress,
                std::move(header),
                std::move(data)
            );
        }
    }
}


/**
 * @brief Internal helper to flush a single buffer.
 */
void PacketStreamEval::flushBufferToFile(PacketBuffer& buffer, size_t& bufferedBytes, const std::string& filename) {
    if (buffer.empty()) return;

    // This check is now redundant, as we only call this if m_saveFilterMatched is true
    // OR from cleanupOnExpiry, which handles the delete.
    // For safety, we'll check the save flag *before* logging.
    if (!m_saveFilterMatched) {
        buffer.clear();
        bufferedBytes = 0;
        return;
    }
    
    Logger::log("Stream " + m_id + ": Flushing " 
              + std::to_string(buffer.size()) 
              + " packets to " + filename);
    
    // *** Actual pcap_dump logic would go here ***
    // NOTE: You need a pcap_t handle to create a dumper.
    // pcap_t* pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
    // pcap_dumper_t* dumper = pcap_dump_open_append(pcap_handle, filename.c_str());
    // if (dumper) {
    //    for (auto& pair : buffer) {
    //        pcap_dump((u_char*)dumper, pair.first.get(), pair.second.get());
    //    }
    //    pcap_dump_close(dumper);
    // }
    // pcap_close(pcap_handle);
    
    m_totalPacketsSaved += buffer.size();
    buffer.clear();
    bufferedBytes = 0;
}


void PacketStreamEval::flushPacketsToDisk() {
    if (m_streamMode == StreamMode::COMBINED) {
        std::string filename = m_fileNameBase + ".pcap";
        flushBufferToFile(m_packetHistory_ingress, m_bufferedBytes_ingress, filename);
    } else {
        std::string f_ingress = m_fileNameBase + "_client.pcap";
        std::string f_egress = m_fileNameBase + "_server.pcap";
        flushBufferToFile(m_packetHistory_ingress, m_bufferedBytes_ingress, f_ingress);
        flushBufferToFile(m_packetHistory_egress, m_bufferedBytes_egress, f_egress);
    }
}

/**
 * @brief Runs final logic on stream expiry.
 */
void PacketStreamEval::cleanupOnExpiry() {
    // 1. Flush any remaining packets (this only writes if m_saveFilterMatched is true)
    flushPacketsToDisk();
    
    // 2. Print summary (if enabled)
    if (globalOptions.streamSummary) {
        printSummary();
    }
    
    // 3. Check save flag and delete file(s) if not matched
    if (!m_saveFilterMatched) {
        // This is the only place we delete. flushPacketsToDisk() always writes.
        if (m_streamMode == StreamMode::COMBINED) {
            std::string filename = m_fileNameBase + ".pcap";
            Logger::log("Stream " + m_id + ": Save filter not matched. Deleting: " + filename);
            std::remove(filename.c_str());
        } else {
            std::string f_ingress = m_fileNameBase + "_client.pcap";
            std::string f_egress = m_fileNameBase + "_server.pcap";
            Logger::log("Stream " + m_id + ": Save filter not matched. Deleting: " + f_ingress + " and " + f_egress);
            std::remove(f_ingress.c_str());
            std::remove(f_egress.c_str());
        }
    } else {
        Logger::log("Stream " + m_id + ": Save filter matched. Keeping files.");
    }
}

/**
 * @brief Prints the collected statistics for this stream to the logger.
 */
void PacketStreamEval::printSummary() const {
    std::lock_guard<std::mutex> lock(m_gapVectorMutex); // Protects gaps/histogram

    std::ostringstream oss;
    oss << "\n--- Stream Summary: " << m_id << " ---\n";
    oss << "  Total Packets Rcvd: " << m_totalPacketsReceived << "\n";
    oss << "  Total Bytes Rcvd:   " << m_totalBytesReceived << "\n";
    oss << "  Total Packets Saved:  " << m_totalPacketsSaved.load() << "\n";
    oss << "  Save Filter Matched: " << (m_saveFilterMatched ? "YES" : "NO") << "\n";

    if (!m_interPacketGaps.empty()) {
        uint64_t sum = std::accumulate(m_interPacketGaps.begin(), m_interPacketGaps.end(), 0ULL);
        uint64_t avg = sum / m_interPacketGaps.size();
        auto minmax = std::minmax_element(m_interPacketGaps.begin(), m_interPacketGaps.end());
        
        oss << "  Inter-Packet Gap (us):\n";
        oss << "    Avg: " << avg << " | Min: " << *minmax.first << " | Max: " << *minmax.second << "\n";
        oss << "  Latency Histogram (us):\n";
        for (auto const& [bucket, count] : m_latencyHistogram) {
            oss << "    <= " << std::setw(7) << bucket << " : " << count << " packets\n";
        }
    }
    oss << "--------------------------------------\n";
    Logger::log(oss.str()); // Use logger so it's thread-safe
}

/**
 * @brief Sets this stream's timeout based on its protocols.
 *
 * This checks the protocols used in the filter (m_protocolsUsed)
 * and selects the "longest" timeout, as TCP is stateful.
 * You can change this logic (e.g., to "shortest") if you prefer.
 */
void PacketStreamEval::determineTimeout(const TimeoutMap& timeoutMap) {
    auto default_it = timeoutMap.find(0); // 0 == DEFAULT
    m_myTimeout = default_it->second;

    // Find the longest timeout for the protocols this stream uses
    // A more complex way would be to inspect the ProtocolStack_t
    // For now, we base it on the *triggers* created.
    
    if (m_protocolsUsed.count("TCP")) {
        auto it = timeoutMap.find(IPPROTO_TCP);
        if (it != timeoutMap.end() && it->second > m_myTimeout) {
            m_myTimeout = it->second;
        }
    } else if (m_protocolsUsed.count("UDP")) {
        auto it = timeoutMap.find(IPPROTO_UDP);
        if (it != timeoutMap.end() && it->second > m_myTimeout) {
            m_myTimeout = it->second;
        }
    }
    
    Logger::log("Stream " + m_id + ": Set timeout to " + std::to_string(m_myTimeout.count()) + "s");
}

} // namespace pcapabvparser
