/**
 * @file ConfigParser.h
 * @brief Defines a parser for protocol timeout configuration.
 */

#ifndef __CONFIG_PARSER_H__
#define __CONFIG_PARSER_H__

#include "PluggableMap.h"
#include <string>
#include <chrono>

namespace pcapabvparser {

// Map of (Protocol Number, Timeout in Seconds)
using TimeoutMap = PluggableUnorderedMap<int, std::chrono::seconds>;

// Map of (Alias Name, Filter String)
using AliasMap = PluggableUnorderedMap<std::string, std::string>;

/**
 * @class ConfigParser
 * @brief Parses a key=value config file for protocol timeouts.
 */
class ConfigParser {
public:
    /**
     * @brief Parses the timeout config file.
     *
     * File format should be key-value pairs (key = value), one per line.
     * Comments are supported using '#'.
     *
     * Protocol names are: TCP, UDP, ICMP, GRE, IPIP, DEFAULT
     *
     * @par Example timeout.conf:
     * @code
     * # Default timeout for all non-specified protocols
     * DEFAULT = 60
     *
     * # TCP streams time out after 10 minutes
     * TCP = 600
     *
     * # UDP is connectionless, shorter timeout
     * UDP = 30
     * @endcode
     *
     * @param filename The path to the config file.
     * @return A map of protocol numbers (IPPROTO_TCP, etc.) to their timeouts.
     */
    static TimeoutMap parseTimeouts(const std::string& filename);

    /**
     * @brief Parses the filter alias file.
     *
     * File format should be key-value pairs (key = value), one per line.
     * The value is the entire string after the '='.
     *
     * @par Example aliases.conf:
     * @code
     * # Find 3-way handshake
     * handshake = (TCP.IsSyn() AND !TCP.IsAck()) OR (TCP.IsSyn() AND TCP.IsAck())
     *
     * # Find all pings
     * pings = ICMP.Type() == 8
     * @endcode
     *
     * @param filename The path to the alias file.
     * @return A map of alias names to filter strings.
     */
    static AliasMap parseAliasFile(const std::string& filename); // <-- NEW

private:
    static int protocolToNumber(const std::string& name);
};

} // namespace pcapabvparser
#endif // __CONFIG_PARSER_H__