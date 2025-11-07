/**
 * @file Logger.cpp
 * @brief Instantiates the static mutex for the Logger class.
 */

/*
 * Author: James Mathewson
 * Date: 6 November 2025
 * Version: 0.7 beta 
 */

#include "Logger.h"

namespace pcapabvparser { // <-- WRAPPER ADDED

// Define the static mutex
std::mutex Logger::m_mutex;

} // namespace pcapabvparser  <-- WRAPPER ADDED
