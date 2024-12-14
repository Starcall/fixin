#pragma once

#include "DataTokenizer.h"
#include "FileHeaderTokenizer.h"
#include "PacketHeaderTokenizer.h"

namespace pcap_parser
{

struct FileHeaderValues
{
    uint32_t MagicNumber = 0;
    uint16_t MajorVersion = 0;
    uint16_t MinorVersion = 0;
    uint32_t Reserved1 = 0;
    uint32_t Reserved2 = 0;
    uint32_t SnapLen = 0;
    uint32_t LinkType = 0;
    enum Endian
    {
        BigEndian,
        LittleEndian
    } EndianType;

};

std::ostream& operator<<(std::ostream& os, const FileHeaderValues& header);


struct PacketHeaderValues
{
    uint32_t Timestamp = 0;
    uint32_t SecondTimestamp = 0;
    uint32_t CapturedLength = 0;
    uint32_t OriginalLength= 0;
};

struct PacketDataValues
{
    std::vector<Byte> Payload;
    bool HasFCS = false;
};

class ParserPCAP
{
public:
    ParserPCAP(std::string const& fileName);

    bool ParseToJson();
// TODO MAKE PRIVATE
public:
    bool ParseFileHeader(FileHeaderValues &parsedValues);
    bool ParsePacketHeader(PacketHeaderValues &parsedValues);
    bool ParsePacketData(PacketDataValues &parsedValues);

    std::string m_fileName;

    DataTokenizer m_dataTokenizer;
    FileHeaderTokenizer m_fileHeaderTokenizer;
    PacketHeaderTokenizer m_packetHeaderTokenizer;

    Logger m_logger;
};
    
} // namespace pcap_parser
