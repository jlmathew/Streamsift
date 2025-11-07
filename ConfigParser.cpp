/**
 * @file ConfigParser.cpp
 * @brief Implementation of the ConfigParser.
 */

/*
 * Author: James Mathewson
 * Date: 6 November 2025
 * Version: 0.7 beta 
 */


#include "ConfigParser.h"
#include "Logger.h"
#include <fstream>
#include <sstream>
#include <netinet/in.h> // For IPPROTO_TCP, etc.

namespace pcapabvparser {

// Helper to convert string names to protocol numbers
int ConfigParser::protocolToNumber(const std::string& name) {
    if (name == "TCP") return IPPROTO_TCP;
    if (name == "UDP") return IPPROTO_UDP;
    if (name == "ICMP") return IPPROTO_ICMP;
    if (name == "GRE") return 47; // IPPROTO_GRE
    if (name == "IPIP") return IPPROTO_IPIP;
    if (name == "DEFAULT") return 0; // Use 0 for default
    return -1; // Unknown
}

TimeoutMap ConfigParser::parseTimeouts(const std::string& filename) {
    TimeoutMap timeouts;
    if (filename.empty()) {
        Logger::log("Warning: No timeout config file provided. Using defaults.");
        // Set some safe defaults
        timeouts[IPPROTO_TCP] = std::chrono::seconds(300);
        timeouts[IPPROTO_UDP] = std::chrono::seconds(30);
        timeouts[0] = std::chrono::seconds(60); // Default
        return timeouts;
    }
    
    std::ifstream infile(filename);
    if (!infile.is_open()) {
        Logger::log("Warning: Could not open timeout config file: " + filename + ". Using defaults.");
        timeouts[IPPROTO_TCP] = std::chrono::seconds(300);
        timeouts[IPPROTO_UDP] = std::chrono::seconds(30);
        timeouts[0] = std::chrono::seconds(60); // Default
        return timeouts;
    }

    std::string line;
    int line_num = 0;
    while (std::getline(infile, line)) {
        line_num++;
        // Remove comments
        if (auto pos = line.find('#'); pos != std::string::npos) {
            line = line.substr(0, pos);
        }
        
        std::stringstream ss(line);
        std::string key, eq, value;
        if (!(ss >> key >> eq >> value) || key.empty() || eq != "=" || value.empty()) {
            continue; // Skip empty or malformed lines
        }
        
        int protoNum = protocolToNumber(key);
        if (protoNum == -1) {
            Logger::log("Warning: Unknown protocol '" + key + "' in config line " + std::to_string(line_num));
            continue;
        }
        
        try {
            long seconds = std::stol(value);
            timeouts[protoNum] = std::chrono::seconds(seconds);
        } catch (const std::exception& e) {
            Logger::log("Warning: Invalid timeout value '" + value + "' for " + key);
        }
    }
    
    // Ensure there is a default
    if (timeouts.find(0) == timeouts.end()) {
        timeouts[0] = std::chrono::seconds(60);
    }
    
    Logger::log("Loaded " + std::to_string(timeouts.size()) + " timeout rules.");
    return timeouts;
}

/**
 * @brief Parses a key = value file, where value can contain spaces.
 */
AliasMap ConfigParser::parseAliasFile(const std::string& filename) {
    AliasMap aliases;
    if (filename.empty()) {
        return aliases; // No file, return empty map
    }

    std::ifstream infile(filename);
    if (!infile.is_open()) {
        Logger::log("Warning: Could not open alias file: " + filename);
        return aliases;
    }

    std::string line;
    int line_num = 0;
    while (std::getline(infile, line)) {
        line_num++;
        if (auto pos = line.find('#'); pos != std::string::npos) {
            line = line.substr(0, pos); // Remove comments
        }
        
        auto eq_pos = line.find('=');
        if (eq_pos == std::string::npos || eq_pos == 0) {
            continue; // Skip lines without '=' or starting with '='
        }

        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);

        // Trim whitespace from key
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);

        // Trim whitespace from value
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);

        if (key.empty() || value.empty()) {
            continue;
        }

        aliases[key] = value;
    }
    
    Logger::log("Loaded " + std::to_string(aliases.size()) + " filter aliases.");
    return aliases;
}

} // namespace pcapabvparser
