/**
 * @file Globals.h
 * @brief Defines global variables, primarily for cross-thread signaling.
 */

/*
 * Author: James Mathewson
 * Date: 6 November 2025
 * Version: 0.7 beta 
 */


#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#include <atomic>

/**
 * @brief Global atomic flag to signal all threads to shut down.
 *
 * It is declared 'extern' here and defined in main.cpp.
 * Threads should check this flag in their main loops to exit gracefully.
 */
extern std::atomic<bool> g_done;

#endif // __GLOBALS_H__
