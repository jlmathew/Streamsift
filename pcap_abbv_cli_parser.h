/**
 * @file pcap_abbv_cli_parser.h
 * @brief Defines the command-line parser and global options struct.
 * @version 0.8
 */

/*
 * Author: James Mathewson
 * Date: 6 November 2025
 * Version: 0.7 beta 
 */


#ifndef PCAP_ABBV_CLI_PARSER_H
#define PCAP_ABBV_CLI_PARSER_H

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <stdexcept>
#include <tuple>
#include <cstring>
#include <set>
#include <sstream>
#include "PluggableMap.h" // For map type

namespace pcapabvparser
{

/// @brief The public version string.
extern std::string version;

/**
 * @struct globalOptions_t
 * @brief A struct to hold all global configuration options parsed from the CLI.
 */
struct globalOptions_t
{
    /** @brief Max total storage in bytes for *all* streams before forcing flushes. (Not yet implemented) */
    uint64_t bufferSizePerTotalFlush;
    
    /** @brief Number of packets to save *before* a "Tag" filter match. */
    uint32_t bufferPacketsBefore;
    
    /** @brief Number of packets to save *after* a "Tag" filter match. */
    uint32_t bufferPacketsAfter;
    
    /** @brief Max total storage in bytes *per stream* before forcing a flush. */
    uint32_t bufferSizePerStreamFlush;
    
    /** @brief If true, combine all saved streams into a single pcap file. (Not yet implemented) */
    bool combinePacketsIntoPcap;
    
    /** @brief If true, print a summary for each stream upon expiry/shutdown. */
    bool streamSummary;
    
    /** @brief A string to prepend to all saved pcap filenames. */
    std::string preName;
    
    /** @brief The filter string (or alias) for tagging packets of interest (x-before/y-after). */
    std::string pcapPacketOfInterestFilter;
    
    /** @brief The filter string (or alias) for marking a stream to be saved. */
    std::string pcapPacketTriggerToSaveFilter;
    
    /** @brief The path to the protocol timeout configuration file. */
    std::string protocolTimeoutConfigFileName;
    
    /** @brief The path to the filter alias configuration file. */
    std::string filterAliasFile;
    
    /** @brief The path to an offline pcap file to read (disables live capture). */
    std::string inputFile;
    
    /** @brief The network interface name for live capture (e.g., "eth0"). */
    std::string interfaceName;
    
    /** @brief The number of consumer threads (0 = single-threaded mode). */
    uint32_t numConsumerThreads;
    
    /** @brief Snapshot length: max packet size to capture (live) or process (offline). */
    uint32_t snapshotLength;
    
    /** @brief A set of ports (e.g., 443, 8443) to identify as TLS. */
    std::set<uint16_t> tlsPorts;

    /**
     * @brief How to store streams: "combined" (default) or "separate" (ingress/egress).
     */
    std::string streamMode;

    /**
     * @brief Default constructor setting all default values.
     */
    globalOptions_t() :
        bufferSizePerTotalFlush(30000000),
        bufferPacketsBefore(10),
        bufferPacketsAfter(7),
        bufferSizePerStreamFlush(30000),
        combinePacketsIntoPcap(false),
        streamSummary(true),
        inputFile(""),
        interfaceName(""),
        numConsumerThreads(1),
        snapshotLength(65535),
        streamMode("combined")
    {
        tlsPorts.insert(443);
    }
    
    // (Destructor and copy ops are default)

    /**
     * @brief Prints all currently set options to std::cout.
     */
    void printOptions()
    {
        std::cout << "Current Global Options:\n"
                  << "  (bufferSizePerTotalFlush): " << bufferSizePerTotalFlush << "\n"
                  << "  (bufferPacketsBefore): " << bufferPacketsBefore << "\n"
                  << "  (bufferPacketsAfter): " << bufferPacketsAfter << "\n"
                  << "  (bufferSizePerStreamFlush): " << bufferSizePerStreamFlush << "\n"
                  << "  (combinePacketsIntoPcap): " << (combinePacketsIntoPcap ? "true" : "false") << "\n"
                  << "  (streamSummary): " << (streamSummary ? "true" : "false") << "\n"
                  << "  (preName): " << preName << "\n"
                  << "  (pcapPacketOfInterestFilter): " << pcapPacketOfInterestFilter << "\n"
                  << "  (pcapPacketTriggerToSaveFilter): " << pcapPacketTriggerToSaveFilter << "\n"
                  << "  (protocolTimeoutConfigFileName): " << protocolTimeoutConfigFileName << "\n"
                  << "  (filterAliasFile): " << filterAliasFile << "\n"
                  << "  (inputFile): " << inputFile << "\n"
                  << "  (interfaceName): " << interfaceName << "\n"
                  << "  (numConsumerThreads): " << numConsumerThreads << "\n"
                  << "  (snapshotLength): " << snapshotLength << "\n";
        
        std::cout << "  (tlsPorts): ";
        for(auto port : tlsPorts) { std::cout << port << ","; }
        std::cout << "\n";
        
        std::cout << "  (streamMode): " << streamMode << "\n";
    }
};

/// @brief Global instance of the options struct, defined in pcap_abbv_cli_parser.cpp
extern globalOptions_t globalOptions;

/**
 * @class cli_parser
 * @brief Parses command-line arguments and populates the globalOptions struct.
 */
class cli_parser
{
public:
    /**
     * @brief Default constructor.
     */
    cli_parser() = default;
    
    /**
     * @brief Constructor that immediately parses arguments.
     * @param argc Argument count from main().
     * @param options Argument vector from main().
     */
    cli_parser(int argc, char* options[]);
    
    /**
     * @brief Default destructor.
     */
    virtual ~cli_parser() = default;

    /**
     * @brief Parses the raw command-line arguments.
     * @param argc Argument count.
     * @param options Array of argument strings.
     */
    void inputRawOptions(int argc, char* options[]);
        
private:
    /// @brief Map of CLI strings (e.g., "--help") to handler functions.
    PluggableUnorderedMap<std::string, std::function<void(const char*)>> m_clioptions;
};

}
#endif // PCAP_ABBV_CLI_PARSER_H
