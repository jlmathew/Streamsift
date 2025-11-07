/**
 * @file Benchmark.h
 * @brief A lightweight, compile-time timer for performance benchmarking.
 *
 * This file provides a simple ScopedTimer class. If the BENCHMARK_THREAD
 * macro is defined, it will measure the time from its creation to its
 * destruction and add it to a thread-local atomic variable.
 *
 * If the macro is *not* defined, the class is empty and all calls
 * compile to zero instructions, incurring no runtime overhead.
 */

#ifndef __BENCHMARK_H__
#define __BENCHMARK_H__

#include <chrono>
#include <atomic>
#include <string>

namespace pcapabvparser { // <-- WRAPPER ADDED

// --- Thread-local accumulators ---

/// @brief Thread-local accumulator for total nanoseconds spent in processing.
extern thread_local std::atomic<uint64_t> g_thread_proc_time_ns;

/// @brief Thread-local accumulator for total packets processed.
extern thread_local std::atomic<uint64_t> g_thread_proc_packets;


#ifdef BENCHMARK_THREAD

/**
 * @class ScopedTimer
 * @brief Measures execution time within its scope and adds to a thread-local total.
 *
 * On creation, it records the start time.
 * On destruction (when it goes out of scope), it records the end time,
 * calculates the duration, and adds it to g_thread_proc_time_ns.
 */
class ScopedTimer {
public:
    ScopedTimer() : m_start(std::chrono::high_resolution_clock::now()) {
        g_thread_proc_packets.fetch_add(1, std::memory_order_relaxed);
    }

    ~ScopedTimer() {
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - m_start).count();
        g_thread_proc_time_ns.fetch_add(duration, std::memory_order_relaxed);
    }

private:
    std::chrono::time_point<std::chrono::high_resolution_clock> m_start;
};

/**
 * @brief Dumps the benchmark results for the current thread to a string.
 * @param thread_id The ID of the current thread.
 * @return A string formatted with the benchmark results.
 */
inline std::string GetBenchmarkResults(size_t thread_id) {
    uint64_t total_ns = g_thread_proc_time_ns.load();
    uint64_t total_pkts = g_thread_proc_packets.load();
    if (total_pkts == 0) return "";

    uint64_t avg_ns = total_ns / total_pkts;
    std::string s = "Benchmark Results [Thread " + std::to_string(thread_id) + "]:\n"
                    + "  Total Pkts: " + std::to_string(total_pkts) + "\n"
                    + "  Total Time: " + std::to_string(total_ns / 1'000'000.0) + " ms\n"
                    + "  Avg Pkt Time: " + std::to_string(avg_ns) + " ns/pkt\n";
    return s;
}

#else

// --- Zero-overhead versions when BENCHMARK_THREAD is OFF ---

/**
 * @class ScopedTimer
 * @brief A no-op version of the timer for release builds.
 *
 * This class is empty and all its methods are inline, resulting
 * in zero generated code and zero runtime overhead.
 */
class ScopedTimer {
public:
    // Constructor and destructor do nothing.
    ScopedTimer() {}
    ~ScopedTimer() {}
};

/**
 * @brief Returns an empty string when benchmarking is disabled.
 * @return An empty std::string.
 */
inline std::string GetBenchmarkResults(size_t) {
    return "";
}

#endif // BENCHMARK_THREAD

} // namespace pcapabvparser  <-- WRAPPER ADDED
#endif // __BENCHMARK_H__