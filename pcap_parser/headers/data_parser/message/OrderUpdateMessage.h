#pragma once
#include "include/Enums.h"
#include "include/Values.h"
#include "../../../utils/utils.hpp"
#include "BaseMessage.h"

namespace pcap_parser
{
namespace data_parser
{
namespace sbe_parser
{
class OrderUpdateMessage : public BaseMessage
{
public:
    OrderUpdateMessage() = default;
    OrderUpdateMessage(message::MessageHeaderValues const& header) 
        : BaseMessage(header)
    {}
    OrderUpdateMessage(OrderUpdateMessage const& other) : 
        BaseMessage(other.m_SBEHeader),
        MDEntryID(other.MDEntryID),
        MDEntryPx(other.MDEntryPx),
        MDEntrySize(other.MDEntrySize),
        MDFlags(other.MDFlags),
        MDFlags2(other.MDFlags2),
        SecurityID(other.SecurityID),
        RptSeq(other.RptSeq),
        MDUpdateAction(other.MDUpdateAction),
        MDEntryType(other.MDEntryType)
    {}
    OrderUpdateMessage(OrderUpdateMessage&& other) noexcept : 
        BaseMessage(std::move(other.m_SBEHeader)),
        MDEntryID(std::move(other.MDEntryID)),
        MDEntryPx(std::move(other.MDEntryPx)),
        MDEntrySize(std::move(other.MDEntrySize)),
        MDFlags(std::move(other.MDFlags)),
        MDFlags2(std::move(other.MDFlags2)),
        SecurityID(std::move(other.SecurityID)),
        RptSeq(std::move(other.RptSeq)),
        MDUpdateAction(std::move(other.MDUpdateAction)),
        MDEntryType(std::move(other.MDEntryType))
    {}
    int64_t MDEntryID = 0;
    utils::Decimal<-5> MDEntryPx = utils::Decimal<-5>(0);
    int64_t MDEntrySize = 0;
    uint64_t MDFlags = 0;
    uint64_t MDFlags2 = 0;
    int32_t SecurityID = 0;
    uint32_t RptSeq = 0;
    uint8_t MDUpdateAction = 0;
    char MDEntryType = 0;
    static size_t GetDataSizeInBytes()
    {
        return 50;
    }
    friend std::ostream& operator<<(std::ostream& os, const OrderUpdateMessage& message) 
    {
        os << "OrderUpdateMessage:\n";
        os << "  MDEntryID         : " << message.MDEntryID << "\n";
        os << "  MDEntryPx         : " << message.MDEntryPx << "\n";
        os << "  MDEntrySize       : " << message.MDEntrySize << "\n";
        os << "  MDFlags           : " << message.MDFlags << "\n";
        os << "  MDFlags2          : " << message.MDFlags2 << "\n";
        os << "  SecurityID        : " << message.SecurityID << "\n";
        os << "  RptSeq            : " << message.RptSeq << "\n";
        os << "  MDUpdateAction    : " << static_cast<unsigned>(message.MDUpdateAction) << "\n";
        os << "  MDEntryType       : " << message.MDEntryType << "\n";
        return os;
    }
};

inline void to_json(nlohmann::json& j, const pcap_parser::data_parser::sbe_parser::OrderUpdateMessage& msg)
{
    j = nlohmann::json
    {
        { "MessageType",     "OrderUpdate"},
        { "MDEntryID",       msg.MDEntryID },
        { "MDEntryPx",       DecimalToString(msg.MDEntryPx) },
        { "MDEntrySize",     msg.MDEntrySize },
        { "MDFlags",         msg.MDFlags },
        { "MDFlags2",        msg.MDFlags2 },
        { "SecurityID",      msg.SecurityID },
        { "RptSeq",          msg.RptSeq },
        { "MDUpdateAction",  static_cast<unsigned>(msg.MDUpdateAction) },
        { "MDEntryType",     std::string(1, msg.MDEntryType) }
    };
}

} // namespace sbe_parser
} // namespace data_parser
} // namespace pcap_parser
