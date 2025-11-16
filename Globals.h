/**
 * @file Globals.h
 * @author James Mathewson
 * @version 1.0.0 beta
 * @brief Defines global variables, primarily for cross-thread signaling and stats.
 */

#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#include <atomic>
#include <cstdint>

// Signal to all threads to exit
extern std::atomic<bool> g_done;

// --- Global Debug Counters ---
extern std::atomic<uint64_t> g_total_packets_read;
extern std::atomic<uint64_t> g_total_packets_dropped;

// Track every unique stream key ever seen
extern std::atomic<uint64_t> g_total_streams_created;

// Track streams that actually matched the "Save" filter and were written to disk
extern std::atomic<uint64_t> g_total_streams_saved;

// --- NEW: Active Stream Tracking ---
// Tracks how many streams are currently in memory across all threads.
// Useful for spotting memory leaks or "stuck" streams.
extern std::atomic<int64_t>  g_current_active_streams;

// High-water mark of concurrent streams.
extern std::atomic<uint64_t> g_max_active_streams;

#endif // __GLOBALS_H__
