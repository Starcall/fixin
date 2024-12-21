#pragma once

#include <cstdlib>
#include <vector>
#include <array>
#include "iostream"

#include "Enums.h"

// TODO add namespaces

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

    MarketDataHeaderValues marketDataHeaderValues;
};

struct SBEMessageHeadervalues
{
    uint16_t BlockLength;
    uint16_t TemplateID;
    uint16_t SchemaID;
    uint16_t Version;
};

struct BasicSBEMessageValues
{
    BasicSBEMessageValues() = default;
    BasicSBEMessageValues(BasicSBEMessageValues const& other) : Type(other.Type)
    {}
    uint16_t Type = 0;
    virtual ~BasicSBEMessageValues() {};
};
} // namespace pcap_parser
