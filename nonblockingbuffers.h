/**
 * @file nonblockingbuffers.h
 * @author James Mathewson
 * @version 1.2.1 (Cleaned: Removed Checksum)
 * @brief Buffer definitions. Strict move semantics for memory safety.
 */

#ifndef _nonblockingbuffers_h__
#define _nonblockingbuffers_h__

#include <vector>
#include <atomic>
#include <optional>
#include <memory>
#include <cstddef>
#include <iostream>
#include <pcap/pcap.h>
#include "pcapkey.h"

// --- DEBUG CONFIGURATION ---
#ifdef _DEBUGBLOCKING_
    #include <mutex>
    #include <deque>
    #include <condition_variable>
#endif

namespace pcapabvparser {

struct pktBufferData_t {
    std::unique_ptr<pcap_pkthdr> pktHeader;
    std::unique_ptr<uint8_t[]> pkt;
    std::unique_ptr<PacketOffsets_t> protoOffset;
    std::unique_ptr<std::vector<uint8_t>> key;
    std::unique_ptr<ProtocolStack_t> protoStack;
    uint32_t index = 0;

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

    // Disable Copy
    pktBufferData_t(const pktBufferData_t&) = delete;
    pktBufferData_t& operator=(const pktBufferData_t&) = delete;

    // Enable Move
    pktBufferData_t(pktBufferData_t&&) = default;
    pktBufferData_t& operator=(pktBufferData_t&&) = default;
};

template<typename T>
class IQueue {
public:
    virtual ~IQueue() = default;
    virtual bool push(T&& item) = 0;
    virtual std::optional<T> pop() = 0;
    virtual size_t getMaxUsage() const = 0;
};

#ifdef _DEBUGBLOCKING_
// --- BLOCKING MUTEX IMPLEMENTATION (Debug Only) ---
template<typename T, size_t Size>
class NonBlockingCircularBuffer : public IQueue<T> {
private:
    std::deque<T> buffer;
    std::mutex m_mutex;
    size_t max_usage = 0;

public:
    NonBlockingCircularBuffer() {}

    bool push(T&& item) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (buffer.size() >= Size) return false;
        buffer.push_back(std::move(item));
        if (buffer.size() > max_usage) max_usage = buffer.size();
        return true;
    }

    std::optional<T> pop() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (buffer.empty()) return std::nullopt;
        T item = std::move(buffer.front());
        buffer.pop_front();
        return item;
    }

    size_t getMaxUsage() const override {
        return max_usage;
    }
};

#else
// --- ATOMIC LOCK-FREE IMPLEMENTATION (Production) ---
template<typename T, size_t Size>
class NonBlockingCircularBuffer : public IQueue<T> {
private:
    std::vector<std::optional<T>> buffer;
    alignas(64) std::atomic<size_t> head{0};
    alignas(64) std::atomic<size_t> tail{0};
    std::atomic<size_t> max_usage{0};

public:
    NonBlockingCircularBuffer() : buffer(Size) {}

    bool push(T&& item) override {
        size_t current_head = head.load(std::memory_order_relaxed);
        size_t next_head = (current_head + 1) % Size;
        size_t current_tail = tail.load(std::memory_order_acquire);

        if (next_head == current_tail) {
            return false;
        }

        buffer[current_head] = std::move(item);
        head.store(next_head, std::memory_order_release);

        size_t usage = (current_head >= current_tail) ? (current_head - current_tail) : (Size - current_tail + current_head);
        size_t current_max = max_usage.load(std::memory_order_relaxed);
        if (usage > current_max) max_usage.store(usage, std::memory_order_relaxed);

        return true;
    }

    std::optional<T> pop() override {
        size_t current_tail = tail.load(std::memory_order_relaxed);
        if (current_tail == head.load(std::memory_order_acquire)) {
            return std::nullopt;
        }

        std::optional<T> item = std::move(buffer[current_tail]);
        buffer[current_tail].reset();
        tail.store((current_tail + 1) % Size, std::memory_order_release);
        return item;
    }

    size_t getMaxUsage() const override {
        return max_usage.load(std::memory_order_relaxed);
    }
};
#endif // _DEBUGBLOCKING_

}
#endif
