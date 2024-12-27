#pragma once

#include "include/Enums.h"
#include "include/Values.h"
#include "PacketDataTokenizer.h"
#include "FileHeaderTokenizer.h"
#include "PacketHeaderTokenizer.h"

namespace pcap_parser
{


std::ostream& operator<<(std::ostream& os, const FileHeaderValues& header);
std::ostream& operator<<(std::ostream& os, const PacketHeaderValues& header);
std::ostream& operator<<(std::ostream& os, const PacketDataValues& data);
class ParserPCAP
{
public:
    ParserPCAP(std::string const& fileName);

    void ResetTokenizersTerminals();

    // Maybe make it private
    bool ParseFileHeader(FileHeaderValues &parsedValues);
    bool ParsePacketHeader(PacketHeaderValues &parsedValues, FileHeaderValues const& metadata);
    bool ParsePacketData(PacketDataValues &parsedValues, PacketHeaderValues const& packetMetadata, FileHeaderValues const& fileMetadata);

    std::string m_fileName;

    PacketDataTokenizer m_dataTokenizer;
    FileHeaderTokenizer m_fileHeaderTokenizer;
    PacketHeaderTokenizer m_packetHeaderTokenizer;

    Logger m_logger;
};
    
} // namespace pcap_parser
