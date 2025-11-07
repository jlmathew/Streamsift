/**
 * @file nonblockingbuffers.h
 * @brief Defines a non-blocking SPSC/MPSC circular buffer (queue).
 *
 * This file provides the IQueue interface and its concrete implementation,
 * NonBlockingCircularBuffer, which is a wait-free, array-based ring buffer.
 * It is used for all inter-thread communication.
 *
 * It also defines the data (pktBufferData_t) that is passed in the queues.
 */

/*
 * Author: James Mathewson
 * Date: 6 November 2025
 * Version: 0.7 beta 
 */


#ifndef _nonblockingbuffers_h__
#define _nonblockingbuffers_h__

#include <vector>
#include <atomic>
#include <optional>
#include <memory>
#include <cstddef> // for size_t
#include <pcap/pcap.h> // For pcap_pkthdr
#include "pcapkey.h" // For PacketOffsets_t, key, and ProtocolStack_t

namespace pcapabvparser {

/**
 * @struct pktBufferData_t
 * @brief The data structure passed between the producer (main)
 * and consumer threads.
 *
 * This struct holds all necessary per-packet data, moved into
 * smart pointers to manage memory lifetime across threads.
 */
struct pktBufferData_t {
    std::unique_ptr<pcap_pkthdr> pktHeader;
    std::unique_ptr<uint8_t[]> pkt;
    std::unique_ptr<PacketOffsets_t> protoOffset;
    std::unique_ptr<std::vector<uint8_t>> key;
    std::unique_ptr<ProtocolStack_t> protoStack; // The protocol stack
    uint32_t index = 0; // The target consumer thread index

    pktBufferData_t(std::unique_ptr<pcap_pkthdr> header,
                    std::unique_ptr<uint8_t[]> data,
                    std::unique_ptr<PacketOffsets_t> offset,
                    std::unique_ptr<std::vector<uint8_t>> keyData,
                    std::unique_ptr<ProtocolStack_t> stackData,
                    uint32_t idx = 0)
        : pktHeader(std::move(header)),
          pkt(std::move(data)),
          protoOffset(std::move(offset)),
          key(std::move(keyData)),
          protoStack(std::move(stackData)),
          index(idx) {}
};

/**
 * @class IQueue
 * @brief An abstract interface for a queue.
 *
 * This allows the consumer_pcap_process_thread function to accept
 * any queue implementation (including mocks) without being
 * templated, achieving type erasure.
 *
 * @tparam T The type of item held in the queue.
 */
template<typename T>
class IQueue {
public:
    virtual ~IQueue() = default;
    
    /**
     * @brief Pushes an item into the queue.
     * @param item The item to push (moved).
     * @return true if the push was successful, false if the queue was full.
     */
    virtual bool push(T&& item) = 0;
    
    /**
     * @brief Pops an item from the queue.
     * @return An std::optional containing the item if successful,
     * or std::nullopt if the queue was empty.
     */
    virtual std::optional<T> pop() = 0;
};

/**
 * @class NonBlockingCircularBuffer
 * @brief A concrete, fixed-size, wait-free, array-based ring buffer.
 *
 * Implements the IQueue interface.
 *
 * @tparam T The type of item to store.
 * @tparam Size The fixed-size of the buffer (must be a power of 2
 * for best performance, though not strictly required by this impl).
 */
template<typename T, size_t Size>
class NonBlockingCircularBuffer : public IQueue<T> {
private:
    std::vector<std::optional<T>> buffer;
    std::atomic<size_t> head{0};
    std::atomic<size_t> tail{0};

public:
    NonBlockingCircularBuffer() : buffer(Size) {}

    bool push(T&& item) override {
        size_t current_head = head.load(std::memory_order_relaxed);
        size_t next_head = (current_head + 1) % Size;

        if (next_head == tail.load(std::memory_order_acquire)) {
            // Queue is full
            return false;
        }

        buffer[current_head] = std::move(item);
        head.store(next_head, std::memory_order_release);
        return true;
    }

    std::optional<T> pop() override {
        size_t current_tail = tail.load(std::memory_order_relaxed);

        if (current_tail == head.load(std::memory_order_acquire)) {
            // Queue is empty
            return std::nullopt;
        }

        std::optional<T> item = std::move(buffer[current_tail]);
        buffer[current_tail].reset(); // Free the slot
        tail.store((current_tail + 1) % Size, std::memory_order_release);
        return item;
    }
};

} //end namespace
#endif // __nonblockingbuffers_h__
