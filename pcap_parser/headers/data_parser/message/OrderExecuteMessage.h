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

class OrderExecutionMessage : public BaseMessage
{
public:
    OrderExecutionMessage() = default;
    OrderExecutionMessage(message::MessageHeaderValues const& header)
        : BaseMessage(header)
    {}

    OrderExecutionMessage(OrderExecutionMessage const& other) : 
        BaseMessage(other.m_SBEHeader),
        MDEntryID(other.MDEntryID),
        MDEntryPx(other.MDEntryPx),
        MDEntrySize(other.MDEntrySize),
        LastPx(other.LastPx),
        LastQty(other.LastQty),
        TradeID(other.TradeID),
        MDFlags(other.MDFlags),
        MDFlags2(other.MDFlags2),
        SecurityID(other.SecurityID),
        RptSeq(other.RptSeq),
        MDUpdateAction(other.MDUpdateAction),
        MDEntryType(other.MDEntryType)
    {}

    OrderExecutionMessage(OrderExecutionMessage&& other) noexcept : 
        BaseMessage(std::move(other.m_SBEHeader)),
        MDEntryID(std::move(other.MDEntryID)),
        MDEntryPx(std::move(other.MDEntryPx)),
        MDEntrySize(std::move(other.MDEntrySize)),
        LastPx(std::move(other.LastPx)),
        LastQty(std::move(other.LastQty)),
        TradeID(std::move(other.TradeID)),
        MDFlags(std::move(other.MDFlags)),
        MDFlags2(std::move(other.MDFlags2)),
        SecurityID(std::move(other.SecurityID)),
        RptSeq(std::move(other.RptSeq)),
        MDUpdateAction(std::move(other.MDUpdateAction)),
        MDEntryType(std::move(other.MDEntryType))
    {}

    int64_t MDEntryID = 0;
    utils::Decimal<5> MDEntryPx = utils::Decimal<5>(0);
    int64_t MDEntrySize = 0;
    utils::Decimal<5> LastPx = utils::Decimal<5>(0);
    int64_t LastQty = 0;
    int64_t TradeID = 0;
    uint64_t MDFlags = 0;
    uint64_t MDFlags2 = 0;
    int32_t SecurityID = 0;
    uint32_t RptSeq = 0;
    uint8_t MDUpdateAction = 0;
    char MDEntryType = 0;

    static size_t GetDataSizeInBytes()
    {
        return 74;
    }
    // consider that null value is  present in data 
    static size_t GetDataSizeInBytesTechincalTrades()
    {
        return 66;
    }
    //otherwise
    static size_t GetDataSizeInBytesTechincalTradesWithoutNull()
    {
        return 58;
    }

    friend std::ostream& operator<<(std::ostream& os, const OrderExecutionMessage& message) 
    {
        os << "OrderExecutionMessage:\n";
        os << "  MDEntryID         : " << message.MDEntryID << "\n";
        os << "  MDEntryPx         : " << message.MDEntryPx << "\n";
        os << "  MDEntrySize       : " << message.MDEntrySize << "\n";
        os << "  LastPx            : " << message.LastPx << "\n";
        os << "  LastQty           : " << message.LastQty << "\n";
        os << "  TradeID           : " << message.TradeID << "\n";
        os << "  MDFlags           : " << message.MDFlags << "\n";
        os << "  MDFlags2          : " << message.MDFlags2 << "\n";
        os << "  SecurityID        : " << message.SecurityID << "\n";
        os << "  RptSeq            : " << message.RptSeq << "\n";
        os << "  MDUpdateAction    : " << static_cast<unsigned>(message.MDUpdateAction) << "\n";
        os << "  MDEntryType       : " << message.MDEntryType << "\n";
        return os;
    }
};

} // namespace sbe_parser
} // namespace data_parser
} // namespace pcap_parser
