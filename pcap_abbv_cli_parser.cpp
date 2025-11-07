/**
 * @file pcap_abbv_cli_parser.cpp
 * @brief Implementation of the command-line parser.
 */

#include "pcap_abbv_cli_parser.h"
#include <vector>
#include <string>
#include <tuple>
#include <functional>

namespace pcapabvparser
{

/// @brief The public version string.
std::string version = "0.9 alpha";

/// @brief Global instance of the options struct.
struct globalOptions_t globalOptions;

/**
 * @brief Prints the full help text to std::cout.
 */
void printHelp();

/**
 * @brief A static vector defining all available CLI options.
 *
 * This vector is the single source of truth for parsing CLI arguments
 * and for printing the help text.
 *
 * Each tuple contains:
 * - {string} long name (e.g., "--bufferflushsize")
 * - {string} short name (e.g., "-f")
 * - {string} help text
 * - {lambda} function to set the corresponding globalOption
 */
const std::vector<std::tuple<std::string, std::string, std::string, std::function<void(const char*)>>> helpStrings =
{
    {
        "--bufferflushsize", "-f", "maximum total storage bytes for all streams before flushing",
        [](const char* arg) { globalOptions.bufferSizePerTotalFlush = std::stoull(arg); }
    },
    {
        "--bufferpacketsizebefore", "-b", "number of packets to save before a packet of interest",
        [](const char* arg) { globalOptions.bufferPacketsBefore = std::stoul(arg); }
    },
    {
        "--bufferpacketsizeafter", "-a", "number of packets to save, after a packet of interest",
        [](const char* arg) { globalOptions.bufferPacketsAfter = std::stoul(arg); }
    },
    {
        "--streamsummary", "-s", "enable per-stream summary on shutdown (true/false)",
        [](const char* arg) { globalOptions.streamSummary = (strncmp(arg, "true", 4) == 0); }
    },
    {
        "--prename", "-n", "prefix name for saved pcap files",
        [](const char* arg) { globalOptions.preName = arg; }
    },
    {
        "--tagPacketFilter", "-t", "pcap abbv filter (or alias) to tag packets of interest",
        [](const char* arg) { globalOptions.pcapPacketOfInterestFilter = arg; }
    },
    {
        "--savePacketFilter", "-p", "pcap abbv filter (or alias) to mark streams for saving",
        [](const char* arg) { globalOptions.pcapPacketTriggerToSaveFilter = arg; }
    },
    {
        "--protoTimeoutConfig", "-c", "file name for protocol timeout config file",
        [](const char* arg) { globalOptions.protocolTimeoutConfigFileName = arg; }
    },
    {
        "--aliases", "-A", "file name for filter aliases (e.g., 'handshake = ...')",
        [](const char* arg) { globalOptions.filterAliasFile = arg; }
    },
    {
        "--threads", "-j", "number of consumer threads (0 = single-threaded mode)",
        [](const char* arg) { globalOptions.numConsumerThreads = std::stoul(arg); }
    },
    {
        "--snaplen", "-S", "snapshot length (max packet size to capture/process)",
        [](const char* arg) { globalOptions.snapshotLength = std::stoul(arg); }
    },
    {
        "--tls-ports", "-P", "comma-separated list of ports to parse as TLS (e.g., 443,8443)",
        [](const char* arg) {
            globalOptions.tlsPorts.clear(); // Clear defaults
            std::stringstream ss(arg);
            std::string portStr;
            while (std::getline(ss, portStr, ',')) {
                if (!portStr.empty()) {
                    globalOptions.tlsPorts.insert(static_cast<uint16_t>(std::stoul(portStr)));
                }
            }
        }
    },
    {
        "--stream-mode", "-M", "Stream storage mode: 'combined' (default) or 'separate' (ingress/egress files)",
        [](const char* arg) { globalOptions.streamMode = arg; }
    },
    {
        "--file", "-r", "pcap file to read from (disables live capture)",
        [](const char* arg) { globalOptions.inputFile = arg; }
    },
    {
        "--interface", "-i", "interface to capture from (default: 'any')",
        [](const char* arg) { globalOptions.interfaceName = arg; }
    },
    {
        "--help", "-h", "print out help ",
        [](const char*) { printHelp(); globalOptions.printOptions(); exit(0); }
    },
    {
        "--version", "-v", "version",
        [](const char*) { std::cout << "Version:" << version << std::endl; exit(0); }
    }
};

// --- Implementation of cli_parser ---

cli_parser::cli_parser(int argc, char* options[]) {
    inputRawOptions(argc, options);
}

void cli_parser::inputRawOptions(int argc, char* argv[]) {
    // Populate the map from the static vector
    for (const auto& line : helpStrings) {
        m_clioptions[std::get<0>(line)] = std::get<3>(line);
        m_clioptions[std::get<1>(line)] = std::get<3>(line);
    }

    // Parse the actual CLI arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg[0] == '-') {
            const char* value = "true"; // Default for flags
            // Check if next argument is a value and not another option
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                value = argv[++i];
            }

            auto it = m_clioptions.find(arg);
            if (it != m_clioptions.end()) {
                it->second(value);
            } else {
                std::cerr << "Unknown parameter: " << arg << std::endl;
                printHelp();
                exit(1);
            }
        } else {
            std::cerr << "Unexpected argument: " << arg << std::endl;
            printHelp();
            exit(1);
        }
    }
}

// --- Implementation of help function ---

void printHelp() {
    std::cout << "Pcap Abbreviation Parser (Version: " << version << ")\n"
              << "Usage: pcap_parser [OPTIONS]\n\nOptions:\n";
    for (const auto& line : helpStrings) {
        std::string long_opt = std::get<0>(line);
        std::string short_opt = std::get<1>(line);
        std::string help_text = std::get<2>(line);
        
        std::cout << "  " << long_opt << ", " << short_opt << "\n"
                  << "      " << help_text << "\n";
    }
}

} //end of namespace