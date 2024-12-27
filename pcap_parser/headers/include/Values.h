#pragma once

#include <cstdlib>
#include <vector>
#include <array>
#include "iostream"

#include "Enums.h"
#include "json.hpp"
#include "../../utils/utils.hpp"

namespace pcap_parser
{

using Byte = unsigned char;
struct FileHeaderValues
{
    uint32_t MagicNumber = 0;
    uint16_t MajorVersion = 0;
    uint16_t MinorVersion = 0;
    uint32_t Reserved1 = 0;
    uint32_t Reserved2 = 0;
    uint32_t SnapLen = 0;
    uint32_t LinkType = 0;
    enums::Endian EndianType = enums::Endian::None;
};

struct PacketHeaderValues
{
    uint32_t Timestamp = 0;
    uint32_t SecondTimestamp = 0;
    uint32_t CapturedLength = 0;
    uint32_t OriginalLength= 0;
};

struct PacketDataValues
{
    std::vector<Byte> Values;
    bool HasFCS = false;
    uint8_t FCSSize = 0;
};

struct IPv4HeaderValues
{
    uint8_t Version = 0;
    uint8_t IHL = 0;
    uint8_t TypeOfService = 0;
    uint16_t TotalLength = 0;
    uint16_t Identification = 0;
    uint8_t Flags = 0;
    uint16_t FragmentOffset = 0;
    uint8_t TTL = 0;
    uint8_t Protocol = 0;
    uint16_t Checksum = 0;
    uint32_t SourceIP = 0;
    uint32_t DestinationIp = 0;
    std::vector<uint8_t> Options;
};

struct UPDHeaderValues
{
    uint16_t SourcePort;
    uint16_t DestinationPort;
    uint16_t Length;
    uint16_t Checksum;
};

struct MarketDataHeaderValues
{
    uint32_t MsgSeqNum;
    uint16_t MsgSize;
    uint16_t MsgFlags;
    uint64_t SendingTime;
};

struct IncrementalPacketHeaderValues 
{
    uint64_t TransactTime;
    uint32_t ExchangeTradingSessionID;
};

struct BasicProtocolValues
{
    BasicProtocolValues() = default;
    BasicProtocolValues(BasicProtocolValues const& other) : Type(other.Type)
    {}
    uint16_t Type = 0;
    virtual ~BasicProtocolValues() {};
};

struct EthernetHeaderValues : public BasicProtocolValues
{
    EthernetHeaderValues() = default;
    EthernetHeaderValues(EthernetHeaderValues const& other)
        : BasicProtocolValues(other),
          DestinationMac(other.DestinationMac),
          SourceMac(other.SourceMac)
          {}
    virtual ~EthernetHeaderValues() {};
    std::array<Byte, 6> DestinationMac;
    std::array<Byte, 6> SourceMac;
};

struct EthernetIPv4HeaderValues : public EthernetHeaderValues
{
    EthernetIPv4HeaderValues() = default;
    EthernetIPv4HeaderValues(const EthernetHeaderValues& other)
        : EthernetHeaderValues(other)
    {}
    EthernetIPv4HeaderValues(EthernetIPv4HeaderValues const& other)
        : EthernetHeaderValues(other),
          ipv4HeaderValues(other.ipv4HeaderValues)
          {}
    virtual ~EthernetIPv4HeaderValues() {};
    IPv4HeaderValues ipv4HeaderValues;
};

struct EthernetIPv4UDPHeaderValues : public EthernetIPv4HeaderValues
{
    EthernetIPv4UDPHeaderValues() = default;
    EthernetIPv4UDPHeaderValues(const EthernetIPv4HeaderValues& other)
        : EthernetIPv4HeaderValues(other)
    {}
    EthernetIPv4UDPHeaderValues(EthernetIPv4UDPHeaderValues const& other)
        : EthernetIPv4HeaderValues(other),
          udpValues(other.udpValues)
    {}

    virtual ~EthernetIPv4UDPHeaderValues() {};
    UPDHeaderValues udpValues;
};

struct MarketDataUDPHeaderValues : public EthernetIPv4UDPHeaderValues
{
    MarketDataUDPHeaderValues() = default;
    MarketDataUDPHeaderValues(const EthernetIPv4UDPHeaderValues& other)
        : EthernetIPv4UDPHeaderValues(other)
    {}
    MarketDataUDPHeaderValues(MarketDataUDPHeaderValues const& other)
        : EthernetIPv4UDPHeaderValues(other),
          marketDataHeaderValues(other.marketDataHeaderValues)
    {}

    virtual ~MarketDataUDPHeaderValues() {};

    static void to_json(nlohmann::json& j, const MarketDataUDPHeaderValues& val)
    {
        j = nlohmann::json
        {
            {
                "EthernetIPv4UDP", 
                {
                    {"DestinationMac", utils::MacToString(val.DestinationMac)},
                    {"SourceMac",      utils::MacToString(val.SourceMac)},
                    {"Type",           utils::TypeToHexString(val.Type)},
                    {"ipv4HeaderValues", 
                        {
                            {"Version",       val.ipv4HeaderValues.Version},
                            {"IHL",           val.ipv4HeaderValues.IHL},
                            {"Protocol",      val.ipv4HeaderValues.Protocol},
                            {"SourceIP",      utils::ipToDottedDecimal(val.ipv4HeaderValues.SourceIP)},
                            {"DestinationIp", utils::ipToDottedDecimal(val.ipv4HeaderValues.DestinationIp)}
                        }
                    },
                    {"udpValues", 
                        {
                            {"SourcePort",      val.udpValues.SourcePort},
                            {"DestinationPort", val.udpValues.DestinationPort},
                            {"Length",          val.udpValues.Length},
                            {"Checksum",        val.udpValues.Checksum}
                        }
                    }
                }
            },
            {"marketDataHeaderValues", 
                {
                    {"MsgSeqNum",   val.marketDataHeaderValues.MsgSeqNum},
                    {"MsgSize",     val.marketDataHeaderValues.MsgSize},
                    {"MsgFlags",    val.marketDataHeaderValues.MsgFlags},
                    {"SendingTime", utils::nanosecondsToRealTime(val.marketDataHeaderValues.SendingTime)}
                }
            }
        };
    }

    MarketDataHeaderValues marketDataHeaderValues;
};

struct InrementalPacketMDUDPValues : public MarketDataUDPHeaderValues
{
    InrementalPacketMDUDPValues() = default;
    InrementalPacketMDUDPValues(const MarketDataUDPHeaderValues& other)
        : MarketDataUDPHeaderValues(other)
    {}
    InrementalPacketMDUDPValues(InrementalPacketMDUDPValues const& other)
        : MarketDataUDPHeaderValues(other),
          incrementalPacketHeaderValues(other.incrementalPacketHeaderValues)
    {}
    static void to_json(nlohmann::json& j, const InrementalPacketMDUDPValues& val)
    {
        MarketDataUDPHeaderValues::to_json(j, static_cast<const MarketDataUDPHeaderValues&>(val));

        j["IncrementalPacketHeaderValues"] = 
        {
            {"TransactTime",            val.incrementalPacketHeaderValues.TransactTime},
            {"ExchangeTradingSessionID", val.incrementalPacketHeaderValues.ExchangeTradingSessionID}
        };
    }
    virtual ~InrementalPacketMDUDPValues() {};
    IncrementalPacketHeaderValues incrementalPacketHeaderValues;
};

namespace message
{

struct MessageHeaderValues
{
    uint16_t BlockLength;
    uint16_t TemplateID;
    uint16_t SchemaID;
    uint16_t Version;
};

} // namespace message
} // namespace pcap_parser
