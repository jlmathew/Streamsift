/**
 * @file ProtoTrigger.h
 * @author James Mathewson
 * @version 1.1.0 beta (String Support)
 * @brief Defines the base class and subclasses for protocol-specific triggers.
 */

#ifndef __PROTOTRIGGER_H__
#define __PROTOTRIGGER_H__

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <string_view> // <-- NEW
#include "PluggableMap.h"
#include "pcapkey.h"

namespace pcapabvparser {
    class ASTNode;
}

namespace pcapabvparser {

using packetLayerHelper_t = PacketOffsets_t;

// --- Existing Integer Lambda ---
using Func = std::function<int(const std::vector<int>&)>;
using protoLambdaMap = PluggableUnorderedMap<std::string, Func>;

// --- NEW String Lambda ---
// Returns a zero-copy view into the raw packet data.
// If data is not found, it should return an empty string_view.
using StringFunc = std::function<std::string_view(const std::vector<int>&)>;
using protoStringMap = PluggableUnorderedMap<std::string, StringFunc>;
// ---------------------------

class protoTrigger {
protected:
    std::string m_myId;
    protoLambdaMap m_protoMap;
    protoStringMap m_stringMap; // <-- NEW

    packetLayerHelper_t* m_packetLayerHelper = nullptr;
    const uint8_t* m_rawPacketData = nullptr;
    const ProtocolStack_t* m_protoStack = nullptr;

public:
    protoTrigger() = default;
    virtual ~protoTrigger() = default;

    virtual void setCurrentPacket(packetLayerHelper_t* helper, const uint8_t* data, const ProtocolStack_t* stack) {
        m_packetLayerHelper = helper;
        m_rawPacketData = data;
        m_protoStack = stack;
    }
    virtual void createNameLambda() = 0;

    virtual Func* findFunction(const std::string& name) {
        if (m_protoMap.empty()) createNameLambda();
        auto it = m_protoMap.find(name);
        if (it != m_protoMap.end()) return &it->second;
        return nullptr;
    }

    // --- NEW: Find String Function ---
    virtual StringFunc* findStringFunction(const std::string& name) {
        // Ensure lambdas are created (createNameLambda populates both maps)
        if (m_protoMap.empty() && m_stringMap.empty()) createNameLambda();
        auto it = m_stringMap.find(name);
        if (it != m_stringMap.end()) return &it->second;
        return nullptr;
    }
};

// (Subclasses remain the same, they just inherit the new m_stringMap)
class protoTcpTrigger : public std::enable_shared_from_this<protoTcpTrigger>, public virtual protoTrigger { public: static std::shared_ptr<protoTcpTrigger> create() { auto p=std::make_shared<protoTcpTrigger>(); p->createNameLambda(); return p; } private: void createNameLambda() override; };
class protoUdpTrigger : public std::enable_shared_from_this<protoUdpTrigger>, public virtual protoTrigger { public: static std::shared_ptr<protoUdpTrigger> create() { auto p=std::make_shared<protoUdpTrigger>(); p->createNameLambda(); return p; } private: void createNameLambda() override; };
class protoIpv4Trigger : public std::enable_shared_from_this<protoIpv4Trigger>, public virtual protoTrigger { public: static std::shared_ptr<protoIpv4Trigger> create() { auto p=std::make_shared<protoIpv4Trigger>(); p->createNameLambda(); return p; } private: void createNameLambda() override; };
class protoIcmpTrigger : public std::enable_shared_from_this<protoIcmpTrigger>, public virtual protoTrigger { public: static std::shared_ptr<protoIcmpTrigger> create() { auto p=std::make_shared<protoIcmpTrigger>(); p->createNameLambda(); return p; } private: void createNameLambda() override; };
class protoGreTrigger : public std::enable_shared_from_this<protoGreTrigger>, public virtual protoTrigger { public: static std::shared_ptr<protoGreTrigger> create() { auto p=std::make_shared<protoGreTrigger>(); p->createNameLambda(); return p; } private: void createNameLambda() override; };
class protoDnsTrigger : public std::enable_shared_from_this<protoDnsTrigger>, public virtual protoTrigger { public: static std::shared_ptr<protoDnsTrigger> create() { auto p=std::make_shared<protoDnsTrigger>(); p->createNameLambda(); return p; } private: void createNameLambda() override; };
class protoTlsTrigger : public std::enable_shared_from_this<protoTlsTrigger>, public virtual protoTrigger { public: static std::shared_ptr<protoTlsTrigger> create() { auto p=std::make_shared<protoTlsTrigger>(); p->createNameLambda(); return p; } private: void createNameLambda() override; };
class protoSmbTrigger : public std::enable_shared_from_this<protoSmbTrigger>, public virtual protoTrigger { public: static std::shared_ptr<protoSmbTrigger> create() { auto p=std::make_shared<protoSmbTrigger>(); p->createNameLambda(); return p; } private: void createNameLambda() override; };
class protoNfsTrigger : public std::enable_shared_from_this<protoNfsTrigger>, public virtual protoTrigger { public: static std::shared_ptr<protoNfsTrigger> create() { auto p=std::make_shared<protoNfsTrigger>(); p->createNameLambda(); return p; } private: void createNameLambda() override; };

} // namespace pcapabvparser
#endif // __PROTOTRIGGER_H__
