#pragma once

#include <cstdlib>
#include <vector>
#include <array>
#include "iostream"

#include "Enums.h"

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
    std::vector<uint32_t> values;
    std::vector<Byte> tail;
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


} // namespace pcap_parser
