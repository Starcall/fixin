#pragma once

#include <cstdlib>
#include <vector>

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
    Endian EndianType = None;
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

} // namespace pcap_parser
