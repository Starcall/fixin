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

struct BasicProtocolValues
{
    BasicProtocolValues() = default;
    BasicProtocolValues(BasicProtocolValues const& other) : Type(other.Type)
    {}
    uint16_t Type = 0;
    virtual ~BasicProtocolValues() {};
};


struct EthernetDataValues : public BasicProtocolValues
{
    EthernetDataValues() = default;
    EthernetDataValues(EthernetDataValues const& other)
        : BasicProtocolValues(other),
          DestinationMac(other.DestinationMac),
          SourceMac(other.SourceMac),
          Payload(other.Payload) 
          {}
    std::array<Byte, 6> DestinationMac;
    std::array<Byte, 6> SourceMac;
    std::vector<Byte> Payload;
};

} // namespace pcap_parser
