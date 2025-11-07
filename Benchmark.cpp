/**
 * @file Benchmark.cpp
 * @brief Defines the thread-local variables for the benchmark system.
 */

/*
 * Author: James Mathewson
 * Date: 6 November 2025
 * Version: 0.7 beta 
 */


#include "Benchmark.h"

namespace pcapabvparser { // <-- WRAPPER ADDED

// Define the thread-local variables
thread_local std::atomic<uint64_t> g_thread_proc_time_ns{0};
thread_local std::atomic<uint64_t> g_thread_proc_packets{0};

} // namespace pcapabvparser  <-- WRAPPER ADDED
