/**
 * @file pcap_abbv_cli_parser.h
 * @author James Mathewson
 * @version 0.9.22 beta
 * @brief Defines the command-line parser and global options struct.
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
    std::set<uint16_t> dnsPorts;
    std::string streamMode;
    bool createDetectedFile;

    /**
     * @brief If true, truncate TLS packets to only headers and Alerts.
     * Removes potentially sensitive application data.
     */
    bool truncateTlsData;

    /**
     * @brief Set of TLS Alert Descriptions (1-byte codes, 0x00 - 0xFF)
     * that should NOT be truncated, e.g., CloseNotify (0x00).
     */
    std::set<uint8_t> redactAlertExceptions;

    /**
     * @brief If true, merges all saved individual .pcap files into one master file, sorted by timestamp.
     */
    bool mergeOutputFiles;

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
        createDetectedFile(false),
        truncateTlsData(false),
        mergeOutputFiles(false)
    {
        tlsPorts.insert(443);
        dnsPorts.insert(53);
        redactAlertExceptions.insert(0);
    }

    /**
     * @brief Prints all currently set options to std::cout.
     */
    void printOptions()
    {
        std::cout << "Current Global Options:\n"
                  << "  (bufferPacketsBefore): " << bufferPacketsBefore << "\n"
                  << "  (truncateTlsData): " << (truncateTlsData ? "true" : "false") << "\n"
                  << "  (mergeOutputFiles): " << (mergeOutputFiles ? "true" : "false") << "\n"
                  << "  (Redaction Exceptions): ";
        for(auto code : redactAlertExceptions) { std::cout << (int)code << ","; }
        std::cout << "\n";
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
