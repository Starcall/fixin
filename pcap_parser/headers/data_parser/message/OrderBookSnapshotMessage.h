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

class OrderBookSnapshot : public BaseMessage
{
public:
    OrderBookSnapshot() = default;
    OrderBookSnapshot(message::MessageHeaderValues const& header)
        : BaseMessage(header)
    {}

    OrderBookSnapshot(OrderBookSnapshot const& other)
        : BaseMessage(other.m_SBEHeader),
          SecurityID(other.SecurityID),
          LastMsgSeqNumProcessed(other.LastMsgSeqNumProcessed),
          RptSeq(other.RptSeq),
          ExchangeTradingSessionID(other.ExchangeTradingSessionID),
          NoMDEntries(other.NoMDEntries)
    {
        MDElements = other.MDElements;
    }

    OrderBookSnapshot(OrderBookSnapshot&& other) noexcept
        : BaseMessage(std::move(other.m_SBEHeader)),
          SecurityID(std::move(other.SecurityID)),
          LastMsgSeqNumProcessed(std::move(other.LastMsgSeqNumProcessed)),
          RptSeq(std::move(other.RptSeq)),
          ExchangeTradingSessionID(std::move(other.ExchangeTradingSessionID)),
          NoMDEntries(std::move(other.NoMDEntries)),
          MDElements(std::move(other.MDElements))
    {}

    int32_t SecurityID = 0;
    uint32_t LastMsgSeqNumProcessed = 0;
    uint32_t RptSeq = 0;
    uint32_t ExchangeTradingSessionID = 0;
    uint32_t NoMDEntries = 0;

    struct MarketDataEntry {
        int64_t MDEntryID = 0;
        uint64_t TransactTime = 0;
        utils::Decimal<5> MDEntryPx = utils::Decimal<5>(0);
        int64_t MDEntrySize = 0;
        uint64_t MDFlags = 0;
        uint64_t MDFlags2 = 0;
        int64_t TradeID = 0;
        char MDEntryType = 0;
    };

    std::vector<MarketDataEntry> MDElements;

    static size_t GetEntrySizeInBytes()
    {
        return 57;
    }
    static size_t GetDataSizeInBytes()
    {
        // Guaranteed data size
        return 16;
    }
    static uint16_t GetBlockLength(uint32_t NoMDEntries)
    {
        return static_cast<uint16_t>(NoMDEntries & 0xFFFF);
    }
    static uint8_t GetNumInGroup(uint32_t NoMDEntries)
    {
        return static_cast<uint8_t>((NoMDEntries >> 16) & 0xFF);
    }

    friend std::ostream& operator<<(std::ostream& os, const OrderBookSnapshot& snapshot)
    {
        os << "OrderBookSnapshot:\n";
        os << "  SecurityID               : " << snapshot.SecurityID << "\n";
        os << "  LastMsgSeqNumProcessed   : " << snapshot.LastMsgSeqNumProcessed << "\n";
        os << "  RptSeq                   : " << snapshot.RptSeq << "\n";
        os << "  ExchangeTradingSessionID : " << snapshot.ExchangeTradingSessionID << "\n";
        os << "  NoMDEntries num          : " << int(GetNumInGroup(snapshot.NoMDEntries)) << "\n";
        os << "  NoMDEntries size         : " << int(GetBlockLength(snapshot.NoMDEntries)) << "\n";

        for (size_t i = 0; i < snapshot.MDElements.size(); ++i)
        {
            const auto& entry = snapshot.MDElements[i];
            os << "  Entry " << i + 1 << ":\n";
            os << "    MDEntryID          : " << entry.MDEntryID << "\n";
            os << "    TransactTime       : " << utils::nanosecondsToRealTime(entry.TransactTime) << "\n";
            os << "    MDEntryPx          : " << entry.MDEntryPx << "\n";
            os << "    MDEntrySize        : " << entry.MDEntrySize << "\n";
            os << "    MDFlags            : " << entry.MDFlags << "\n";
            os << "    MDFlags2           : " << entry.MDFlags2 << "\n";
            os << "    TradeID            : " << entry.TradeID << "\n";
            os << "    MDEntryType        : " << int(entry.MDEntryType) << "\n";
        }
        return os;
    }
};

} // namespace sbe_parser
} // namespace data_parser
} // namespace pcap_parser
