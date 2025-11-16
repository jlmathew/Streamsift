/**
 * @file pcap_abbv_cli_parser.cpp
 * @author James Mathewson
 * @version 0.9.21 beta
 * @brief Implementation of the command-line parser (Added Merge and Redaction Config).
 */

#include "pcap_abbv_cli_parser.h"
#include <vector>
#include <string>
#include <tuple>
#include <functional>

namespace pcapabvparser
{

// Define global variables
std::string version = "1.1.1 alpha (Merge Support)";
struct globalOptions_t globalOptions;

void printHelp();

/**
 * @brief A static vector defining all available CLI options.
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
        "--create-detected", "-d", "immediately create an empty .detected file when save criteria met",
        [](const char* arg) { globalOptions.createDetectedFile = (strncmp(arg, "true", 4) == 0); }
    },
    {
        "--truncate-tls", "-T", "truncate TLS application data (removes app data from save files)",
        [](const char* arg) { globalOptions.truncateTlsData = (strncmp(arg, "true", 4) == 0); }
    },
    {
        "--merge-output", "-m", "merge all individual output pcaps into a single master file",
        [](const char* arg) { globalOptions.mergeOutputFiles = (strncmp(arg, "true", 4) == 0); }
    },
    // --- NEW CLI FLAG IMPLEMENTATION ---
    {
        "--tls-redact-alerts", "-R", "comma-sep list of Alert DESCRIPTIONS (0-255) to EXCLUDE from truncation (e.g., 20,40)",
        [](const char* arg) {
            globalOptions.redactAlertExceptions.clear(); // Clear default 0
            std::stringstream ss(arg);
            std::string codeStr;
            while (std::getline(ss, codeStr, ',')) {
                if (!codeStr.empty()) {
                    try {
                        // Ensure we parse the argument and store the list of exception codes
                        globalOptions.redactAlertExceptions.insert(static_cast<uint8_t>(std::stoul(codeStr)));
                    } catch (...) {}
                }
            }
        }
    },
    // ----------------------------------
    {
        "--dns-ports", "-D", "comma-separated list of ports to force-parse as DNS (e.g., 53,5353)",
        [](const char* arg) {
            globalOptions.dnsPorts.clear();
            std::stringstream ss(arg); std::string portStr;
            while (std::getline(ss, portStr, ',')) {
                if (!portStr.empty()) { globalOptions.dnsPorts.insert(static_cast<uint16_t>(std::stoul(portStr))); }
            }
        }
    },
    {
        "--tls-ports", "-P", "comma-separated list of ports to parse as TLS (e.g., 443,8443)",
        [](const char* arg) {
            globalOptions.tlsPorts.clear();
            std::stringstream ss(arg);
            std::string portStr;
            while (std::getline(ss, portStr, ',')) {
                if (!portStr.empty()) { globalOptions.tlsPorts.insert(static_cast<uint16_t>(std::stoul(portStr))); }
            }
        }
    },
    {
        "--threads", "-j", "number of consumer threads (0 = single-threaded mode)",
        [](const char* arg) { globalOptions.numConsumerThreads = std::stoul(arg); }
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
    for (const auto& line : helpStrings) {
        m_clioptions[std::get<0>(line)] = std::get<3>(line);
        m_clioptions[std::get<1>(line)] = std::get<3>(line);
    }
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg[0] == '-') {
            const char* value = "true";
            if (i + 1 < argc && argv[i + 1][0] != '-') value = argv[++i];
            auto it = m_clioptions.find(arg);
            if (it != m_clioptions.end()) it->second(value);
            else {
                // If it's an unrecognized flag, print help and exit
                std::cerr << "Unknown parameter: " << arg << std::endl;
                printHelp();
                exit(1);
            }
        } else {
            // If it's an argument not starting with '-', treat as unknown
            std::cerr << "Unexpected argument: " << arg << std::endl;
            printHelp();
            exit(1);
        }
    }
}

void printHelp() {
    std::cout << "StreamSift Pcap Parser (Version: " << version << ")\n"
              << "Usage: pcap_parser [OPTIONS]\n\nOptions:\n";
    for (const auto& line : helpStrings) {
        std::cout << "  " << std::get<0>(line) << ", " << std::get<1>(line) << "\n"
                  << "      " << std::get<2>(line) << "\n";
    }
}

} //end of namespace
