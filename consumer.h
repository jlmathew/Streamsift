/**
 * @file Consumer.h
 * @brief Defines the main entry function for a consumer thread.
 */

#ifndef __CONSUMER_H__
#define __CONSUMER_H__

#include <memory>
#include <string>
#include "nonblockingbuffers.h" // For IQueue and pktBufferData_t
#include "ConfigParser.h" // For TimeoutMap

namespace pcapabvparser {

/**
 * @brief The main function for a consumer processing thread.
 *
 * This function runs in a loop, popping packets from its assigned
 * queue, finding or creating a PacketStreamEval object, and
 * passing the packet to it for processing.
 *
 * It also handles graceful shutdown and benchmark reporting.
 *
 * @param id The unique numerical ID for this thread.
 * @param buffer A shared_ptr to this thread's IQueue.
 * @param tagFilter The filter string for "Tagging" packets.
 * @param saveFilter The filter string for "Saving" streams.
 * @param timeoutMap The globally-loaded map of protocol timeouts.
 */
void consumer_pcap_process_thread(
    size_t id,
    std::shared_ptr<IQueue<std::unique_ptr<pktBufferData_t>>> buffer,
    const std::string& tagFilter,
    const std::string& saveFilter,
    const TimeoutMap& timeoutMap);

} // namespace pcapabvparser

#endif // __CONSUMER_H__