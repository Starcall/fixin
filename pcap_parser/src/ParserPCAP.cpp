#include "ParserPCAP.h"

namespace pcap_parser
{
std::ostream& operator<<(std::ostream& os, const FileHeaderValues& header)
{
    os << std::hex << std::showbase << std::uppercase;  // Hexadecimal format with base prefix
    
    os << "MagicNumber: " << header.MagicNumber << "\n";
    os << "MajorVersion: " << std::dec << header.MajorVersion << "\n";  // Decimal format for version numbers
    os << "MinorVersion: " << header.MinorVersion << "\n";
    os << "Reserved1: " << header.Reserved1 << "\n";
    os << "Reserved2: " << header.Reserved2 << "\n";
    os << "SnapLen: " << header.SnapLen << "\n";
    os << "LinkType: " << header.LinkType << "\n";
    
    os << "EndianType: " << (header.EndianType == FileHeaderValues::BigEndian ? "BigEndian" : "LittleEndian") << "\n";

    return os;
}

std::ostream& operator<<(std::ostream& os, const PacketHeaderValues& header)
{
    os << "PacketHeaderValues {" << std::endl;
    os << "  Timestamp: " << header.Timestamp << std::endl;
    os << "  SecondTimestamp: " << header.SecondTimestamp << std::endl;
    os << "  CapturedLength: " << header.CapturedLength << std::endl;
    os << "  OriginalLength: " << header.OriginalLength << std::endl;
    os << "}";
    return os;
}

std::ostream& operator<<(std::ostream& os, const PacketDataValues& data)
{
    os << "PacketDataValues {" << std::endl;

    os << "  Values: [";
    for (size_t i = 0; i < data.values.size(); ++i) {
        os << std::hex << "0x" << data.values[i];
        if (i < data.values.size() - 1) {
            os << ", ";
        }
    }
    os << "]" << std::endl;

    os << "  Tail: [";
    for (size_t i = 0; i < data.tail.size(); ++i) {
        os << std::hex << "0x" << static_cast<int>(data.tail[i]);
        if (i < data.tail.size() - 1) {
            os << ", ";
        }
    }
    os << "]" << std::endl;

    os << "  HasFCS: " << (data.HasFCS ? "true" : "false") << std::endl;
    os << "  FCSSize: " << static_cast<int>(data.FCSSize) << std::endl;

    os << "}";
    return os;
}
ParserPCAP::ParserPCAP(std::string const &fileName) : m_fileName(fileName)
{
    std::shared_ptr<std::ifstream> fileStream = std::make_shared<std::ifstream>(std::ifstream(fileName));
    m_dataTokenizer = DataTokenizer(fileStream);
    m_fileHeaderTokenizer = FileHeaderTokenizer(fileStream);
    m_packetHeaderTokenizer = PacketHeaderTokenizer(fileStream);
}

bool ParserPCAP::ParseToJson()
{
    return false;
}

void ParserPCAP::ResetTokenizersTerminals()
{
    m_fileHeaderTokenizer.ResetTerminal();
    m_dataTokenizer.ResetTerminal();
    m_packetHeaderTokenizer.ResetTerminal();
}

bool ParserPCAP::ParseFileHeader(FileHeaderValues &parsedValues)
{
    m_logger.log(Logger::LogLevel::Info, "ParseFileHeader()");
            
    while (!m_fileHeaderTokenizer.IsLastToken())
    {
        std::unique_ptr<BaseToken> token;
        auto rc = m_fileHeaderTokenizer.ReadToken(token); 
        if (!rc || !token)
        {
            m_logger.log(Logger::LogLevel::Error, "Failed to read header token.");
            return false;
        }
        std::unique_ptr<FileHeaderToken> fileHeaderToken = std::unique_ptr<FileHeaderToken>(dynamic_cast<FileHeaderToken*>(token.release()));
        if (!fileHeaderToken)
        {
                m_logger.log(Logger::LogLevel::Error, "Dynamic cast failed?");
                return false;
        }
        switch(fileHeaderToken->m_tokenIdentity)
        {
            case HeaderTokenIdentity::HeaderNone:
            {
                m_logger.log(Logger::LogLevel::Error, "Failed to recognize token identity");
                return false;
                break;
            }
            case HeaderTokenIdentity::MagicNumber:
            {
                auto value = fileHeaderToken->m_tokenValue;
                const uint32_t MICROSECONDS_VALUE = 0xA1B2C3D4;
                const uint32_t NANOSECONDS_VALUE = 0xA1B23C4D;
                if (value == MICROSECONDS_VALUE || value == NANOSECONDS_VALUE)
                {
                    parsedValues.EndianType = parsedValues.LittleEndian;
                    parsedValues.MagicNumber = value;
                }
                else
                if (__builtin_bswap32(value) == MICROSECONDS_VALUE || __builtin_bswap32(value) == NANOSECONDS_VALUE)
                {
                    parsedValues.EndianType = parsedValues.BigEndian;
                    parsedValues.MagicNumber = __builtin_bswap32(value);
                }
                else
                {
                    m_logger.log(Logger::LogLevel::Error, "Magic number is not recognized");
                    return false;
                
                }
                break;
            }
            case HeaderTokenIdentity::Versions:
            {
                if (parsedValues.EndianType == parsedValues.None){
                    m_logger.log(Logger::LogLevel::Error, "Cannot define endian of the system to parse header");
                    return false;
                }
                if (parsedValues.EndianType == parsedValues.BigEndian)
                {
                    auto value = __builtin_bswap32(fileHeaderToken->m_tokenValue);
                    m_logger.log(Logger::LogLevel::Error, std::to_string(value));
                    
                    parsedValues.MinorVersion = (value >> 16);
                    parsedValues.MajorVersion = value ^ (parsedValues.MinorVersion >> 16);
                }
                else
                {
                    auto value = fileHeaderToken->m_tokenValue;
                    parsedValues.MajorVersion = (value >> 16);
                    parsedValues.MinorVersion = value ^ (parsedValues.MajorVersion >> 16);
                }
                break;
            }
            case HeaderTokenIdentity::Reserved1:
            {
                if (fileHeaderToken->m_tokenValue != 0)
                {
                    m_logger.log(Logger::LogLevel::Info, "Reserved is not empty.");
                }
                break;
            }
            case HeaderTokenIdentity::Reserved2:
            {
                if (fileHeaderToken->m_tokenValue != 0)
                {
                    m_logger.log(Logger::LogLevel::Info, "Reserved is not empty.");
                }
                break;
            }
            case HeaderTokenIdentity::SnapLen:
            {
                if (parsedValues.EndianType == parsedValues.None){
                    m_logger.log(Logger::LogLevel::Error, "Cannot define endian of the system to parse header");
                    return false;
                }
                int32_t value = 0;
                if (parsedValues.EndianType == parsedValues.BigEndian)
                {
                    value = __builtin_bswap32(fileHeaderToken->m_tokenValue);
                }
                else
                {
                    value = fileHeaderToken->m_tokenValue;
                }
                parsedValues.SnapLen = value;
                break;
            }
            case HeaderTokenIdentity::LinkType:
            {
                if (parsedValues.EndianType == parsedValues.None){
                    m_logger.log(Logger::LogLevel::Error, "Cannot define endian of the system to parse header");
                    return false;
                }
                int32_t value = 0;
                if (parsedValues.EndianType == parsedValues.BigEndian)
                {
                    value = __builtin_bswap32(fileHeaderToken->m_tokenValue);
                }
                else
                {
                    value = fileHeaderToken->m_tokenValue;
                }
                parsedValues.LinkType = value;
                break;
            }
        }
    }
    return true;
}

bool ParserPCAP::ParsePacketHeader(PacketHeaderValues &parsedValues, FileHeaderValues const& metadata)
{
    m_logger.log(Logger::LogLevel::Info, "ParsePacketHeader()");
    while (!m_packetHeaderTokenizer.IsLastToken())
    {
        std::unique_ptr<BaseToken> token;
        auto rc = m_packetHeaderTokenizer.ReadToken(token); 
        if (!rc || !token)
        {
            m_logger.log(Logger::LogLevel::Error, "Failed to read packet header token.");
            return false;
        }
        std::unique_ptr<PacketHeaderToken> packetHeaderToken = std::unique_ptr<PacketHeaderToken>(dynamic_cast<PacketHeaderToken*>(token.release()));
        if (!packetHeaderToken)
        {
            m_logger.log(Logger::LogLevel::Error, "Dynamic cast failed?");
            return false;
        }
        auto value = packetHeaderToken->m_tokenValue;
        if (metadata.EndianType == metadata.None)
        {
            m_logger.log(Logger::LogLevel::Error, "Cannot define endian of the system to parse header");
            return false;
        }
        if (metadata.EndianType == metadata.BigEndian)
        {
            value = __builtin_bswap32(packetHeaderToken->m_tokenValue);   
        }
        switch (packetHeaderToken->m_tokenIdentity)
        {
            case PacketTokenIdentity::PacketNone:
            {
                m_logger.log(Logger::LogLevel::Error, "Failed to recognize token identity");
                return false;
                break;
            }        
            case PacketTokenIdentity::Seconds:
            {
                parsedValues.Timestamp = value;
                break;
            }
            case PacketTokenIdentity::SideSeconds:
            {
                parsedValues.SecondTimestamp = value;
                break;
            }
            case PacketTokenIdentity::OriginalLength:
            {
                parsedValues.OriginalLength = value;
                break;
            }
            case PacketTokenIdentity::CapturedLength:
            {
                parsedValues.CapturedLength = value;
                break;
            }
        }
    }
    return true;
}

bool ParserPCAP::ParsePacketData(PacketDataValues &parsedValues, PacketHeaderValues const& packetMetadata, FileHeaderValues const& fileMetadata)
{
    m_logger.log(Logger::LogLevel::Info, "ParsePacketData()");
    m_dataTokenizer.SetDataLength(packetMetadata.CapturedLength);
    std::unique_ptr<BaseToken> token;
    auto rc = m_dataTokenizer.ReadToken(token); 
    if (!rc || !token)
    {
        m_logger.log(Logger::LogLevel::Error, "Failed to read data token.");
        return false;
    }
    std::unique_ptr<DataToken> dataToken = std::unique_ptr<DataToken>(dynamic_cast<DataToken*>(token.release()));
    if (!dataToken)
    {
        m_logger.log(Logger::LogLevel::Error, "Dynamic cast failed?");
        return false;
    }
    //TODO Long operation? Optimize later
    for (auto const& BaseToken : dataToken->m_4BytesValues)
    {
        parsedValues.values.push_back(BaseToken.m_tokenValue);
    }
    parsedValues.tail = dataToken->m_tail;
    auto FCSvalue = (fileMetadata.LinkType >> 28);
    parsedValues.HasFCS = FCSvalue & 8;
    if (parsedValues.HasFCS)
    {
        parsedValues.FCSSize = static_cast<uint8_t>(fileMetadata.LinkType >> 29);
    }
    return true;
}

} // namespace pcap_parser
