/**
 * @file protoTrigger.h
 * @brief Defines the base class for protocol-specific triggers
 * and function providers.
 */

/*
 * Author: James Mathewson
 * Date: 6 November 2025
 * Version: 0.7 beta 
 */


#ifndef __PROTOTRIGGER_H__
#define __PROTOTRIGGER_H__

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include "PluggableMap.h"
#include "pcapkey.h" // For PacketOffsets_t, ProtocolStack_t

// Forward declarations
namespace pcapabvparser {
    class ASTNode;
}

namespace pcapabvparser {

// Use the PacketOffsets_t struct as the helper
using packetLayerHelper_t = PacketOffsets_t;

using Func = std::function<int(const std::vector<int>&)>;
using protoLambdaMap = PluggableUnorderedMap<std::string, Func>;

/**
 * @class protoTrigger
 * @brief Base class for protocol-specific function providers.
 *
 * Each subclass (e.g., protoTcpTrigger) is responsible for
 * registering lambdas (e.g., "TCP.IsSyn") that can be
 * called by the AST.
 *
 * It holds the *current packet context* (helper and data)
 * to allow lambdas to be efficient.
 */
class protoTrigger {
protected:
    std::string m_myId;
    protoLambdaMap m_protoMap;
    
    // --- Current Packet Context ---
    /**
     * @brief Pointer to the current packet's offset helper.
     * This is set by PacketStreamEval *before* tree->eval().
     */
    packetLayerHelper_t* m_packetLayerHelper = nullptr;
    
    /**
     * @brief Pointer to the start of the current packet's raw data.
     * This is set by PacketStreamEval *before* tree->eval().
     */
    const uint8_t* m_rawPacketData = nullptr;

    /**
     * @brief Pointer to the current packet's parsed protocol stack.
     */
    const ProtocolStack_t* m_protoStack = nullptr; // <-- NEW
    // ---

public:
    protoTrigger() = default;
    virtual ~protoTrigger() = default;

    /**
     * @brief Sets the packet context for the *next* AST evaluation.
     * @param helper Pointer to the PacketOffsets_t for the current packet.
     * @param data Pointer to the raw data for the current packet.
     * @param stack Pointer to the ProtocolStack_t for the current packet.
     */
    virtual void setCurrentPacket(packetLayerHelper_t* helper, const uint8_t* data, const ProtocolStack_t* stack) {
        m_packetLayerHelper = helper;
        m_rawPacketData = data;
        m_protoStack = stack; // <-- NEW
    }

    /**
     * @brief Populates the m_protoMap with protocol-specific lambdas.
     *
     * This is called once when the trigger is created.
     */
    virtual void createNameLambda() = 0;

    /**
     * @brief Finds a function by name in this trigger's map.
     * @param name The name of the function (e.g., "TCP.IsSyn").
     * @return A raw pointer to the std::function if found,
     * otherwise nullptr.
     */
    virtual Func* findFunction(const std::string& name) {
        if (m_protoMap.empty()) {
            createNameLambda();
        }
        auto it = m_protoMap.find(name);
        if (it != m_protoMap.end()) {
            return &it->second; // Return a pointer to the function
        }
        return nullptr;
    }
};

// --- NEW Protocol Trigger Classes ---

/**
 * @class protoTcpTrigger
 * @brief Provides TCP-specific functions (e.g., flags, window size).
 */
class protoTcpTrigger : public std::enable_shared_from_this<protoTcpTrigger>,
                        public virtual protoTrigger {
public:
    static std::shared_ptr<protoTcpTrigger> create() {
        auto ptr = std::make_shared<protoTcpTrigger>();
        ptr->createNameLambda();
        return ptr;
    }
private:
    void createNameLambda() override;
};

/**
 * @class protoUdpTrigger
 * @brief Provides UDP-specific functions (e.g., ports).
 */
class protoUdpTrigger : public std::enable_shared_from_this<protoUdpTrigger>,
                        public virtual protoTrigger {
public:
    static std::shared_ptr<protoUdpTrigger> create() {
        auto ptr = std::make_shared<protoUdpTrigger>();
        ptr->createNameLambda();
        return ptr;
    }
private:
    void createNameLambda() override;
};

/**
 * @class protoIpv4Trigger
 * @brief Provides IPv4-specific functions (e.g., length, flags).
 */
class protoIpv4Trigger : public std::enable_shared_from_this<protoIpv4Trigger>,
                         public virtual protoTrigger {
public:
    static std::shared_ptr<protoIpv4Trigger> create() {
        auto ptr = std::make_shared<protoIpv4Trigger>();
        ptr->createNameLambda();
        return ptr;
    }
private:
    void createNameLambda() override;
};

/**
 * @class protoIcmpTrigger
 * @brief Provides ICMP-specific functions (type, code).
 */
class protoIcmpTrigger : public std::enable_shared_from_this<protoIcmpTrigger>,
                         public virtual protoTrigger {
public:
    static std::shared_ptr<protoIcmpTrigger> create() {
        auto ptr = std::make_shared<protoIcmpTrigger>();
        ptr->createNameLambda();
        return ptr;
    }
private:
    void createNameLambda() override;
};

/**
 * @class protoGreTrigger
 * @brief Provides GRE-specific functions.
 */
class protoGreTrigger : public std::enable_shared_from_this<protoGreTrigger>,
                        public virtual protoTrigger {
public:
    static std::shared_ptr<protoGreTrigger> create() {
        auto ptr = std::make_shared<protoGreTrigger>();
        ptr->createNameLambda();
        return ptr;
    }
private:
    void createNameLambda() override;
};

/**
 * @class protoDnsTrigger
 * @brief Provides DNS-specific functions (placeholder).
 */
class protoDnsTrigger : public std::enable_shared_from_this<protoDnsTrigger>,
                        public virtual protoTrigger {
public:
    static std::shared_ptr<protoDnsTrigger> create() {
        auto ptr = std::make_shared<protoDnsTrigger>();
        ptr->createNameLambda();
        return ptr;
    }
private:
    void createNameLambda() override;
};

/**
 * @class protoTlsTrigger
 * @brief Provides TLS-specific functions (placeholder).
 */
class protoTlsTrigger : public std::enable_shared_from_this<protoTlsTrigger>,
                        public virtual protoTrigger {
public:
    static std::shared_ptr<protoTlsTrigger> create() {
        auto ptr = std::make_shared<protoTlsTrigger>();
        ptr->createNameLambda();
        return ptr;
    }
private:
    void createNameLambda() override;
};


} // namespace pcapabvparser
#endif // __PROTOTRIGGER_H__
