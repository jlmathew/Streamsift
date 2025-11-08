/**
 * @file pcap_abbv_cli_parser.h
 * @brief Defines the command-line parser and global options struct.
 * @version 0.9.1
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

extern std::string version;

/**
 * @struct globalOptions_t
 * @brief A struct to hold all global configuration options parsed from the CLI.
 */
struct globalOptions_t
{
    uint64_t bufferSizePerTotalFlush;
    uint32_t bufferPacketsBefore;
    uint32_t bufferPacketsAfter;
    uint32_t bufferSizePerStreamFlush;
    bool combinePacketsIntoPcap;
    bool streamSummary;
    std::string preName;
    std::string pcapPacketOfInterestFilter;
    std::string pcapPacketTriggerToSaveFilter;
    std::string protocolTimeoutConfigFileName;
    std::string filterAliasFile;
    std::string inputFile;
    std::string interfaceName;
    uint32_t numConsumerThreads;
    uint32_t snapshotLength;
    std::set<uint16_t> tlsPorts;
    std::string streamMode;

    /**
     * @brief If true, immediately creates an empty .detected file when save criteria are met.
     * This serves as a real-time flag for external monitoring systems.
     */
    bool createDetectedFile; // <-- NEW

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
        streamMode("combined"),
        createDetectedFile(false) // <-- Default to false
    {
        tlsPorts.insert(443);
    }
    
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
                  << "  (snapshotLength): " << snapshotLength << "\n"
                  << "  (createDetectedFile): " << (createDetectedFile ? "true" : "false") << "\n"; // <-- NEW
        
        std::cout << "  (tlsPorts): ";
        for(auto port : tlsPorts) { std::cout << port << ","; }
        std::cout << "\n";
        
        std::cout << "  (streamMode): " << streamMode << "\n";
    }
};

/// Global instance of the options struct.
extern globalOptions_t globalOptions;

/**
 * @class cli_parser
 * @brief Parses command-line arguments and populates the globalOptions struct.
 */
class cli_parser
{
public:
    cli_parser() = default;
    cli_parser(int argc, char* options[]);
    virtual ~cli_parser() = default;

    /**
     * @brief Parses the raw command-line arguments.
     * @param argc Argument count.
     * @param options Array of argument strings.
     */
    void inputRawOptions(int argc, char* options[]);
    
private:
    /// Map of CLI strings (e.g., "--help") to handler functions.
    PluggableUnorderedMap<std::string, std::function<void(const char*)>> m_clioptions;
};

}
#endif // PCAP_ABBV_CLI_PARSER_H
