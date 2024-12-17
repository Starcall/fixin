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
    
    os << "EndianType: " << (header.EndianType == enums::BigEndian ? "BigEndian" : "LittleEndian") << "\n";

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
        os << std::hex << data.values[i];
        if (i < data.values.size() - 1) {
            os << ", ";
        }
    }
    os << "]" << std::endl;

    os << "  Tail: [";
    for (size_t i = 0; i < data.tail.size(); ++i) {
        os << std::hex << static_cast<int>(data.tail[i]);
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
            case enums::HeaderTokenIdentity::HeaderNone:
            {
                m_logger.log(Logger::LogLevel::Error, "Failed to recognize token identity");
                return false;
                break;
            }
            case enums::HeaderTokenIdentity::MagicNumber:
            {
                auto value = fileHeaderToken->m_tokenValue;
                const uint32_t MICROSECONDS_VALUE = 0xA1B2C3D4;
                const uint32_t NANOSECONDS_VALUE = 0xA1B23C4D;
                if (value == MICROSECONDS_VALUE || value == NANOSECONDS_VALUE)
                {
                    parsedValues.EndianType = enums::Endian::LittleEndian;
                    parsedValues.MagicNumber = value;
                }
                else
                if (__builtin_bswap32(value) == MICROSECONDS_VALUE || __builtin_bswap32(value) == NANOSECONDS_VALUE)
                {
                    parsedValues.EndianType = enums::Endian::BigEndian;
                    parsedValues.MagicNumber = __builtin_bswap32(value);
                }
                else
                {
                    m_logger.log(Logger::LogLevel::Error, "Magic number is not recognized");
                    return false;
                
                }
                break;
            }
            case enums::HeaderTokenIdentity::Versions:
            {
                if (parsedValues.EndianType == enums::Endian::None){
                    m_logger.log(Logger::LogLevel::Error, "Cannot define endian of the system to parse header");
                    return false;
                }
                if (parsedValues.EndianType == enums::Endian::BigEndian)
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
            case enums::HeaderTokenIdentity::Reserved1:
            {
                if (fileHeaderToken->m_tokenValue != 0)
                {
                    m_logger.log(Logger::LogLevel::Info, "Reserved is not empty.");
                }
                break;
            }
            case enums::HeaderTokenIdentity::Reserved2:
            {
                if (fileHeaderToken->m_tokenValue != 0)
                {
                    m_logger.log(Logger::LogLevel::Info, "Reserved is not empty.");
                }
                break;
            }
            case enums::HeaderTokenIdentity::SnapLen:
            {
                if (parsedValues.EndianType == enums::Endian::None){
                    m_logger.log(Logger::LogLevel::Error, "Cannot define endian of the system to parse header");
                    return false;
                }
                int32_t value = 0;
                if (parsedValues.EndianType == enums::Endian::BigEndian)
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
            case enums::HeaderTokenIdentity::LinkType:
            {
                if (parsedValues.EndianType == enums::Endian::None){
                    m_logger.log(Logger::LogLevel::Error, "Cannot define endian of the system to parse header");
                    return false;
                }
                int32_t value = 0;
                if (parsedValues.EndianType == enums::Endian::BigEndian)
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
        if (metadata.EndianType == enums::Endian::None)
        {
            m_logger.log(Logger::LogLevel::Error, "Cannot define endian of the system to parse header");
            return false;
        }
        if (metadata.EndianType == enums::Endian::BigEndian)
        {
            value = __builtin_bswap32(packetHeaderToken->m_tokenValue);   
        }
        switch (packetHeaderToken->m_tokenIdentity)
        {
            case enums::PacketTokenIdentity::PacketNone:
            {
                m_logger.log(Logger::LogLevel::Error, "Failed to recognize token identity");
                return false;
                break;
            }        
            case enums::PacketTokenIdentity::Seconds:
            {
                parsedValues.Timestamp = value;
                break;
            }
            case enums::PacketTokenIdentity::SideSeconds:
            {
                parsedValues.SecondTimestamp = value;
                break;
            }
            case enums::PacketTokenIdentity::OriginalLength:
            {
                parsedValues.OriginalLength = value;
                break;
            }
            case enums::PacketTokenIdentity::CapturedLength:
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
    if (fileMetadata.EndianType == enums::Endian::None)
    {
        m_logger.log(Logger::LogLevel::Error, "Cannot define endian of the system to parse header");
    }
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
    //TODO Long operation? Optimize later? memcpy?
    for (auto const& BaseToken : dataToken->m_4BytesValues)
    {
        if (fileMetadata.EndianType == enums::Endian::BigEndian)
        {
            parsedValues.values.push_back(__builtin_bswap32(BaseToken.m_tokenValue));
        }
        else
        {
            parsedValues.values.push_back(BaseToken.m_tokenValue);
        }
    }
    if (fileMetadata.EndianType == enums::Endian::BigEndian)
    {
        std::transform(dataToken->m_tail.begin(), dataToken->m_tail.end(), parsedValues.tail.begin(), [](uint32_t value)
        {
            return __builtin_bswap32(value);
        });
    }
    else
    {
        parsedValues.tail = dataToken->m_tail;
    }
    auto FCSvalue = (fileMetadata.LinkType >> 28);
    parsedValues.HasFCS = FCSvalue & 8;
    if (parsedValues.HasFCS)
    {
        parsedValues.FCSSize = static_cast<uint8_t>(fileMetadata.LinkType >> 29);
        if (fileMetadata.EndianType == enums::Endian::BigEndian)
        {
            parsedValues.FCSSize = __builtin_bswap32(parsedValues.FCSSize);
        }
    }
    return true;
}

} // namespace pcap_parser
