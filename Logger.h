/**
 * @file Logger.h
 * @brief Defines a simple, thread-safe console logger.
 */

#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <iostream>
#include <string>
#include <mutex>
#include <sstream>

namespace pcapabvparser { // <-- WRAPPER ADDED

/**
 * @class Logger
 * @brief A static, thread-safe logging utility.
 *
 * Provides a simple, mutex-protected interface for writing log messages
 * to std::cerr from multiple threads.
 */
class Logger {
public:
    /**
     * @brief Logs a general message.
     * @param message The message string to log.
     */
    static void log(const std::string& message) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::cerr << "[LOG] " << message << std::endl;
    }

    /**
     * @brief Logs a message from a specific thread.
     * @param thread_id The numerical ID of the logging thread.
     * @param message The message string to log.
     */
    static void log(size_t thread_id, const std::string& message) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::cerr << "[Thread " << thread_id << "] " << message << std::endl;
    }

private:
    /// Mutex to protect std::cerr from concurrent access.
    static std::mutex m_mutex;
};

} // namespace pcapabvparser  <-- WRAPPER ADDED
#endif // __LOGGER_H__