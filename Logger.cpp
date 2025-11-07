/**
 * @file Logger.cpp
 * @brief Instantiates the static mutex for the Logger class.
 */

#include "Logger.h"

namespace pcapabvparser { // <-- WRAPPER ADDED

// Define the static mutex
std::mutex Logger::m_mutex;

} // namespace pcapabvparser  <-- WRAPPER ADDED