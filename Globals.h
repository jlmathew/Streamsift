/**
 * @file Globals.h
 * @author James Mathewson
 * @version 0.9.11 beta
 * @brief Defines global variables, primarily for cross-thread signaling and stats.
 */

#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#include <atomic>

/**
 * @brief Global atomic flag to signal all threads to shut down.
 */
extern std::atomic<bool> g_done;

// --- Global Debug Counters ---
extern std::atomic<uint64_t> g_total_packets_read;
extern std::atomic<uint64_t> g_total_packets_dropped;
extern std::atomic<uint64_t> g_total_streams_created;
extern std::atomic<uint64_t> g_total_streams_saved;

#endif // __GLOBALS_H__
