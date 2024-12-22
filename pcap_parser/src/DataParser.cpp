#include "data_parser/DataParser.h"

#include "iostream"
#include "sstream"
#include <iomanip> 

namespace pcap_parser
{
namespace data_parser
{
std::ostream& operator<<(std::ostream& os, const EthernetHeaderValues& eth) {
    os << "Type: " << static_cast<unsigned>(eth.Type) << "\n"; 
    os << "Destination MAC: ";
    for (size_t i = 0; i < eth.DestinationMac.size(); ++i) {
        os << std::hex << std::setw(2) << std::setfill('0') << (int)eth.DestinationMac[i];
        if (i < eth.DestinationMac.size() - 1) os << ":";
    }
    os << "\nSource MAC: ";
    for (size_t i = 0; i < eth.SourceMac.size(); ++i) {
        os << std::hex << std::setw(2) << std::setfill('0') << (int)eth.SourceMac[i];
        if (i < eth.SourceMac.size() - 1) os << ":";
    }
    os << "\n";
    os << std::dec; // return to decimal output for subsequent fields
    return os;
}



inline std::ostream& operator<<(std::ostream& os, const IPv4HeaderValues& ipv4) {
    os << "Version: " << (unsigned)ipv4.Version << "\n";
    os << "IHL: " << (unsigned)ipv4.IHL << "\n";
    os << "TypeOfService: " << (unsigned)ipv4.TypeOfService << "\n";
    os << "TotalLength: " << ipv4.TotalLength << "\n";
    os << "Identification: " << ipv4.Identification << "\n";
    os << "Flags: " << (unsigned)ipv4.Flags << "\n";
    os << "FragmentOffset: " << ipv4.FragmentOffset << "\n";
    os << "TTL: " << (unsigned)ipv4.TTL << "\n";
    os << "Protocol: " << (unsigned)ipv4.Protocol << "\n";
    os << "Checksum: " << ipv4.Checksum << "\n";
    os << "SourceIP: " << utils::ipToDottedDecimal(ipv4.SourceIP) << "\n";
    os << "DestinationIp: " << utils::ipToDottedDecimal(ipv4.DestinationIp) << "\n";
    os << "Options: ";
    for (auto b : ipv4.Options) {
        os << (unsigned)b << " "; 
    }
    os << "\n";
    return os;
}

std::ostream& operator<<(std::ostream& os, const EthernetIPv4HeaderValues& eth_ipv4) {
    os << static_cast<const EthernetHeaderValues&>(eth_ipv4);
    os << eth_ipv4.ipv4HeaderValues;
    return os;
}
std::ostream& operator<<(std::ostream& os, const UPDHeaderValues& udp)
{
    os << "UDP Header:\n";
    os << "SourcePort: " << udp.SourcePort << "\n";
    os << "DestinationPort: " << udp.DestinationPort << "\n";
    os << "Length: " << udp.Length << "\n";
    os << "Checksum: " << udp.Checksum << "\n";
    return os;
}

std::ostream& operator<<(std::ostream& os, const EthernetIPv4UDPHeaderValues& eth_ipv4_udp)
{
    os << static_cast<const EthernetIPv4HeaderValues&>(eth_ipv4_udp);
    os << eth_ipv4_udp.udpValues;
    return os;
}

std::ostream& operator<<(std::ostream& os, const MarketDataHeaderValues& mdh)
{
    os << "MarketDataHeaderValues:\n";
    os << "  MsgSeqNum   : " << mdh.MsgSeqNum << "\n";
    os << "  MsgSize     : " << mdh.MsgSize << "\n";
    os << "  MsgFlags    : " << mdh.MsgFlags << "\n";
    os << "  SendingTime : " << utils::nanosecondsToRealTime(mdh.SendingTime) << "\n";
    return os;
}

std::ostream& operator<<(std::ostream& os, const IncrementalPacketHeaderValues& values) 
{
    os << "Incremental Packet Header:\n";
    os << "  TransactTime            : " << utils::nanosecondsToRealTime(values.TransactTime) << "\n";
    os << "  ExchangeTradingSessionID: " << values.ExchangeTradingSessionID << "\n";
    return os;
}
std::ostream& operator<<(std::ostream& os, const InrementalPacketMDUDPValues& values) 
{
    os << static_cast<const MarketDataUDPHeaderValues&>(values);
    os << values.incrementalPacketHeaderValues; 
    return os;
}

std::ostream& operator<<(std::ostream& os, const MarketDataUDPHeaderValues& md)
{
    os << static_cast<const EthernetIPv4UDPHeaderValues&>(md);
    os << md.marketDataHeaderValues;
    return os;
}
std::ostream& operator<<(std::ostream& os, const message::MessageHeaderValues& header) 
{
    os << "MessageHeaderValues:\n";
    os << "  BlockLength: " << header.BlockLength << "\n";
    os << "  TemplateID : " << header.TemplateID << "\n";
    os << "  SchemaID   : " << header.SchemaID << "\n";
    os << "  Version    : " << header.Version << "\n";
    return os;
}

bool DataParser::ParseProtocolHeadersData(std::unique_ptr<BasicProtocolValues> &parsedValues)
{
    // TODO log
    switch (m_fileMetadata.LinkType)
    {
        case 1:
        {
            EthernetHeaderValues parsedDataValues;
            auto rc = ParseEthernetProtocolHeader(parsedDataValues);
            if (!rc)
            {
                return false;
            }
            // IPv4
            if (parsedDataValues.Type == 0x0800)
            {
                EthernetIPv4HeaderValues parsedIPv4Values(parsedDataValues);
                
                IPv4HeaderValues parsedIPv4Headervalues;
                rc = ParseIPv4ProtocolHeader(parsedIPv4Headervalues);
                if (!rc)
                {
                    return false;
                }

                parsedIPv4Values.ipv4HeaderValues = parsedIPv4Headervalues;
                // UPD
                if (parsedIPv4Values.ipv4HeaderValues.Protocol == 17)
                {
                    MarketDataUDPHeaderValues parsedMDUDPValues(parsedIPv4Values);    

                    // Parse UDP header
                    UPDHeaderValues parsedUDPHeaderValues;
                    rc = ParseUDPHeader(parsedUDPHeaderValues);
                    if (!rc)
                    {
                        return false;
                    }       
                    parsedMDUDPValues.udpValues = parsedUDPHeaderValues;

                    // Parse MD header
                    MarketDataHeaderValues parsedMDH;
                    rc = ParseMarketDataHeader(parsedMDH);
                    if (!rc)
                    {
                        return false;
                    }
                    parsedMDUDPValues.marketDataHeaderValues = parsedMDH;

                    if (parsedMDH.MsgFlags & 0x8)
                    {
                        // Incremental Packet
                        InrementalPacketMDUDPValues parsedInrementalPacketMDUDPValues(parsedMDUDPValues);
                        // Parse IncrementalPacketHeader
                        IncrementalPacketHeaderValues parsedIncrementalPacketHeaderValues;
                        rc = ParseIncrementalPacketHeader(parsedIncrementalPacketHeaderValues);
                        if (!rc)
                        {
                            return false;
                        }      
                        parsedInrementalPacketMDUDPValues.incrementalPacketHeaderValues = parsedIncrementalPacketHeaderValues;
                        parsedValues = std::make_unique<InrementalPacketMDUDPValues>(parsedInrementalPacketMDUDPValues);
                    }
                    else
                    {
                        // Snapshot Packet
                        parsedValues = std::make_unique<MarketDataUDPHeaderValues>(parsedMDUDPValues);
                    }
                    return true;
                }
                else
                {
                    // NOT IMPLEMENTED
                    return false;
                }
            }
            else    
            {
                // NOT IMPLEMENTED
                return false;
            }
            return true;
        }
        default:
        {
            // NOT IMPLEMENTED
            return false;
        }
    }

}

bool DataParser::ParseMessageHeaderData(message::MessageHeaderValues &parsedValues)
{
    sbe_parser::MessageHeaderTokenizer headerTokenizer(m_data.Values, m_firstUnprocessed);
    while (!headerTokenizer.IsLastToken())
    {
        std::unique_ptr<BaseToken> token;
        if (!headerTokenizer.ReadToken(token) || !token)
        {
            return false;
        }
        sbe_parser::MessageHeaderToken* messageHeaderToken = dynamic_cast<sbe_parser::MessageHeaderToken*>(token.get());
        if (!messageHeaderToken)
        {
            return false;
        }
        switch (messageHeaderToken->m_tokenIdentity)
        {
            case enums::message::MessageHeaderTokenIdenity::MessageHeaderNone:
            {
                return false;
                break;
            }
            case enums::message::MessageHeaderTokenIdenity::BlockLength:
            {
                parsedValues.BlockLength = static_cast<uint16_t>(messageHeaderToken->m_tokenValue);
                break;
            }
            case enums::message::MessageHeaderTokenIdenity::SchemaID:
            {
                parsedValues.SchemaID = static_cast<uint16_t>(messageHeaderToken->m_tokenValue);
                break;
            }
            case enums::message::MessageHeaderTokenIdenity::TemplateID:
            {
                parsedValues.TemplateID = static_cast<uint16_t>(messageHeaderToken->m_tokenValue);
                break;
            }
            case enums::message::MessageHeaderTokenIdenity::Version:
            {
                parsedValues.Version = static_cast<uint16_t>(messageHeaderToken->m_tokenValue);
                break;
            }
        }
    }
    m_firstUnprocessed = headerTokenizer.GetPosition();
    return true;
}

bool DataParser::ParseMessageData(std::unique_ptr<sbe_parser::BaseMessage>& parsedMessage, enums::message::MessageType type)
{
    // I decided to not implement Tokenizers approach here
    // It will be faster, less memory allocation and easily paralled
    // It will be not paralleled in scope of this task
    switch (type)
    {
    case enums::message::MessageType::Unsupported:
    {
        return false;
        break;
    }
    case enums::message::MessageType::OrderUpdate:
    {        
        if (!parsedMessage)
        {
            return false;
        }
        if (m_firstUnprocessed + parsedMessage->m_SBEHeader.BlockLength > m_data.Values.size())
        {
            return false;
        }
        if (parsedMessage->m_SBEHeader.BlockLength != sbe_parser::OrderUpdateMessage::GetDataSizeInBytes())
        {
            return false;
        }
        sbe_parser::OrderUpdateMessage parsed(parsedMessage->m_SBEHeader);
        const uint8_t* current = m_data.Values.data() + m_firstUnprocessed;

        parsed.MDEntryID = utils::readLittleEndian<int64_t>(current);
        current += sizeof(int64_t);

        int64_t mantissa = utils::readLittleEndian<int64_t>(current);
        parsed.MDEntryPx.setMantissa(mantissa);
        current += sizeof(int64_t);

        parsed.MDEntrySize = utils::readLittleEndian<int64_t>(current);
        current += sizeof(int64_t);

        parsed.MDFlags = utils::readLittleEndian<uint64_t>(current);
        current += sizeof(uint64_t);

        parsed.MDFlags2 = utils::readLittleEndian<uint64_t>(current);
        current += sizeof(uint64_t);

        parsed.SecurityID = utils::readLittleEndian<int32_t>(current);
        current += sizeof(int32_t);

        parsed.RptSeq = utils::readLittleEndian<uint32_t>(current);
        current += sizeof(uint32_t);

        parsed.MDUpdateAction = *current;
        current += sizeof(uint8_t);

        parsed.MDEntryType = *current;
        current += sizeof(char);

        m_firstUnprocessed = current - m_data.Values.data();
        parsedMessage = std::make_unique<sbe_parser::OrderUpdateMessage>(parsed);
        break;
    }
    case enums::message::MessageType::OrderExecution:
    {
        if (!parsedMessage)
        {
            return false;
        }
        if (m_firstUnprocessed + parsedMessage->m_SBEHeader.BlockLength > m_data.Values.size())
        {
            return false;
        }
        if (parsedMessage->m_SBEHeader.BlockLength != sbe_parser::OrderExecutionMessage::GetDataSizeInBytes()
            && parsedMessage->m_SBEHeader.BlockLength != sbe_parser::OrderExecutionMessage::GetDataSizeInBytesTechincalTrades()
            && parsedMessage->m_SBEHeader.BlockLength != sbe_parser::OrderExecutionMessage::GetDataSizeInBytesTechincalTradesWithoutNull())
        {
            return false;
        }
        sbe_parser::OrderExecutionMessage parsed(parsedMessage->m_SBEHeader);
        const uint8_t* current = m_data.Values.data() + m_firstUnprocessed;

        parsed.MDEntryID = utils::readLittleEndian<int64_t>(current);
        current += sizeof(int64_t);
        if (parsedMessage->m_SBEHeader.BlockLength == sbe_parser::OrderExecutionMessage::GetDataSizeInBytes()
            || parsedMessage->m_SBEHeader.BlockLength == sbe_parser::OrderExecutionMessage::GetDataSizeInBytesTechincalTrades())
        {
            int64_t mantissa = utils::readLittleEndian<int64_t>(current);
            parsed.MDEntryPx.setMantissa(mantissa);
            current += sizeof(int64_t);
        }
        else
        {
            parsed.MDEntryPx.setMantissa(utils::Decimal<5>::getNullValue());
        }

        if (parsedMessage->m_SBEHeader.BlockLength == sbe_parser::OrderExecutionMessage::GetDataSizeInBytes())
        {
            parsed.MDEntrySize = utils::readLittleEndian<int64_t>(current);
            current += sizeof(int64_t);
        }
        else
        {
            parsed.MDEntrySize = 0;
        }


        int64_t lastMantissa = utils::readLittleEndian<int64_t>(current);
        parsed.LastPx.setMantissa(lastMantissa);
        current += sizeof(int64_t);

        parsed.LastQty = utils::readLittleEndian<int64_t>(current);
        current += sizeof(int64_t);

        parsed.TradeID = utils::readLittleEndian<int64_t>(current);
        current += sizeof(int64_t);

        parsed.MDFlags = utils::readLittleEndian<uint64_t>(current);
        current += sizeof(uint64_t);

        parsed.MDFlags2 = utils::readLittleEndian<uint64_t>(current);
        current += sizeof(uint64_t);

        parsed.SecurityID = utils::readLittleEndian<int32_t>(current);
        current += sizeof(int32_t);

        parsed.RptSeq = utils::readLittleEndian<uint32_t>(current);
        current += sizeof(uint32_t);

        parsed.MDUpdateAction = *current;
        current += sizeof(uint8_t);

        parsed.MDEntryType = *current;
        current += sizeof(char);

        m_firstUnprocessed += parsed.m_SBEHeader.BlockLength;
        parsedMessage = std::make_unique<sbe_parser::OrderExecutionMessage>(parsed);
        break;
    }
    case enums::message::MessageType::OrderBookSnapshot:
    {
        if (!parsedMessage)
        {
            return false;
        }

        if (m_firstUnprocessed + parsedMessage->m_SBEHeader.BlockLength > m_data.Values.size())
        {
            return false;
        }

        if (parsedMessage->m_SBEHeader.BlockLength < sbe_parser::OrderBookSnapshot::GetDataSizeInBytes())
        {
            return false;
        }

        sbe_parser::OrderBookSnapshot parsed(parsedMessage->m_SBEHeader);
        const uint8_t* current = m_data.Values.data() + m_firstUnprocessed;

        parsed.SecurityID = utils::readLittleEndian<int32_t>(current);
        current += sizeof(int32_t);

        parsed.LastMsgSeqNumProcessed = utils::readLittleEndian<uint32_t>(current);
        current += sizeof(uint32_t);

        parsed.RptSeq = utils::readLittleEndian<uint32_t>(current);
        current += sizeof(uint32_t);

        parsed.ExchangeTradingSessionID = utils::readLittleEndian<uint32_t>(current);
        current += sizeof(uint32_t);

        parsed.NoMDEntries = utils::readLittleEndian<uint16_t>(current);
        current += sizeof(uint16_t);
        parsed.NoMDEntries += static_cast<uint32_t>(utils::readLittleEndian<uint8_t>(current)) << 16;
        current += sizeof(uint8_t);

        // it is impossible to understand specification there
        // it says that some fields could be not transmitted
        // but we do not have any delimeter or bitmask of skipped values
        // lets just hope they include null values always
        assert(m_firstUnprocessed + 
            sbe_parser::OrderBookSnapshot::GetDataSizeInBytes() +
            sbe_parser::OrderBookSnapshot::GetNumInGroup(parsed.NoMDEntries) * sbe_parser::OrderBookSnapshot::GetBlockLength(parsed.NoMDEntries) <= m_data.Values.size());
        for (uint8_t i = 0; i < sbe_parser::OrderBookSnapshot::GetNumInGroup(parsed.NoMDEntries); i++)
        {
            sbe_parser::OrderBookSnapshot::MarketDataEntry entry;

            entry.MDEntryID = utils::readLittleEndian<int64_t>(current);
            current += sizeof(int64_t);

            entry.TransactTime = utils::readLittleEndian<uint64_t>(current);
            current += sizeof(uint64_t);

            int64_t mantissa = utils::readLittleEndian<int64_t>(current);
            entry.MDEntryPx.setMantissa(mantissa);
            current += sizeof(int64_t);

            entry.MDEntrySize = utils::readLittleEndian<int64_t>(current);
            current += sizeof(int64_t);

            entry.TradeID = utils::readLittleEndian<int64_t>(current);
            current += sizeof(int64_t);
            
            entry.MDFlags = utils::readLittleEndian<uint64_t>(current);
            current += sizeof(uint64_t);

            entry.MDFlags2 = utils::readLittleEndian<uint64_t>(current);
            current += sizeof(uint64_t);

            entry.MDEntryType = *current;
            current += sizeof(char);

            parsed.MDElements.push_back(entry);
        }

        m_firstUnprocessed += current - (m_data.Values.data() + m_firstUnprocessed);
        parsedMessage = std::make_unique<sbe_parser::OrderBookSnapshot>(parsed);
        break;
    }

    default:
    {
        return false;
        break;
    }
    }
    return true;
}

bool DataParser::ParseEthernetProtocolHeader(EthernetHeaderValues &parsedValues)
{
    // TODO add log
    EthernetHeaderTokenizer headerTokenizer = EthernetHeaderTokenizer(m_data.Values);
    while (!headerTokenizer.IsLastToken())
    {
        std::unique_ptr<BaseToken> token;
        auto rc = headerTokenizer.ReadToken(token);
        if (!rc || !token)
        {
            return false;
        }
        std::unique_ptr<EthernetHeaderToken> ethernetHeaderToken = std::unique_ptr<EthernetHeaderToken>(dynamic_cast<EthernetHeaderToken*>(token.release()));
        if (!ethernetHeaderToken)
        {
            return false;
        }
        switch (ethernetHeaderToken->m_tokenIdentity)
        {
            case enums::EthernetHeaderTokenIdentity::DestinationMac:
            {
                // memcpy?
                parsedValues.DestinationMac = ethernetHeaderToken->m_bigTokenValue;
                break;
            }
            case enums::EthernetHeaderTokenIdentity::SourceMac:
            {
                //ditto
                parsedValues.SourceMac = ethernetHeaderToken->m_bigTokenValue;
                break;
            }
            case enums::EthernetHeaderTokenIdentity::Type:
            {
                parsedValues.Type = static_cast<uint16_t>(ethernetHeaderToken->m_tokenValue & 0xFFFF);
                break;
            }
            case enums::EthernetHeaderTokenIdentity::EthernetNone:
            {
                return false;
                break;
            }
        }
    }
    m_firstUnprocessed = headerTokenizer.GetPosition();
    return true;
}


bool DataParser::ParseIPv4ProtocolHeader(IPv4HeaderValues & parsedValues)
{
    IPv4HeaderTokenizer headerTokenizer(m_data.Values, m_firstUnprocessed);
    while (!headerTokenizer.IsLastToken())
    {
        std::unique_ptr<BaseToken> token;
        auto rc = headerTokenizer.ReadToken(token);
        if (!rc || !token)
        {
            return false;
        }
        std::unique_ptr<IPv4HeaderToken> ipv4HeaderToken = std::unique_ptr<IPv4HeaderToken>(dynamic_cast<IPv4HeaderToken*>(token.release()));
        if (!ipv4HeaderToken)
        {
            return false;
        }
        switch (ipv4HeaderToken->m_tokenIdentity)
        {
            case enums::IPv4HeaderTokenIdentity::Version:
                parsedValues.Version = static_cast<uint8_t>(ipv4HeaderToken->m_tokenValue);
                break;
            case enums::IPv4HeaderTokenIdentity::IHL:
                parsedValues.IHL = static_cast<uint8_t>(ipv4HeaderToken->m_tokenValue);
                break;
            case enums::IPv4HeaderTokenIdentity::TypeOfService:
                parsedValues.TypeOfService = static_cast<uint8_t>(ipv4HeaderToken->m_tokenValue);
                break;
            case enums::IPv4HeaderTokenIdentity::TotalLength:
                parsedValues.TotalLength = static_cast<uint16_t>(ipv4HeaderToken->m_tokenValue);
                break;
            case enums::IPv4HeaderTokenIdentity::Identification:
                parsedValues.Identification = static_cast<uint16_t>(ipv4HeaderToken->m_tokenValue);
                break;
            case enums::IPv4HeaderTokenIdentity::Flags:
                parsedValues.Flags = static_cast<uint8_t>(ipv4HeaderToken->m_tokenValue);
                break;
            case enums::IPv4HeaderTokenIdentity::FragmentOffset:
                parsedValues.FragmentOffset = static_cast<uint16_t>(ipv4HeaderToken->m_tokenValue);
                break;
            case enums::IPv4HeaderTokenIdentity::TTL:
                parsedValues.TTL = static_cast<uint8_t>(ipv4HeaderToken->m_tokenValue);
                break;
            case enums::IPv4HeaderTokenIdentity::Protocol:
                parsedValues.Protocol = static_cast<uint8_t>(ipv4HeaderToken->m_tokenValue);
                break;
            case enums::IPv4HeaderTokenIdentity::Checksum:
                parsedValues.Checksum = static_cast<uint16_t>(ipv4HeaderToken->m_tokenValue);
                break;
            case enums::IPv4HeaderTokenIdentity::SourceIP:
                parsedValues.SourceIP = static_cast<uint32_t>(ipv4HeaderToken->m_tokenValue);
                break;
            case enums::IPv4HeaderTokenIdentity::DestinationIp:
                parsedValues.DestinationIp = static_cast<uint32_t>(ipv4HeaderToken->m_tokenValue);
                break;
            case enums::IPv4HeaderTokenIdentity::Options:
                break;
            case enums::IPv4HeaderTokenIdentity::IPv4None:
                return false;
        }
    }
    m_firstUnprocessed = headerTokenizer.GetPosition();
    return true;
}
bool DataParser::ParseUDPHeader(UPDHeaderValues& parsedValues)
{
    UDPHeaderTokenizer headerTokenizer(m_data.Values, m_firstUnprocessed);
    while (!headerTokenizer.IsLastToken())
    {
        std::unique_ptr<BaseToken> token;
        if (!headerTokenizer.ReadToken(token) || !token)
        {
            return false;
        }
        UDPHeaderToken* udpToken = dynamic_cast<UDPHeaderToken*>(token.get());
        if (!udpToken)
        {
            return false;
        }
        switch (udpToken->m_tokenIdentity)
        {
            case enums::UPDHeaderTokenIdentity::SourcePort:
                parsedValues.SourcePort = static_cast<uint16_t>(udpToken->m_tokenValue);
                break;
            case enums::UPDHeaderTokenIdentity::DestinationPort:
                parsedValues.DestinationPort = static_cast<uint16_t>(udpToken->m_tokenValue);
                break;
            case enums::UPDHeaderTokenIdentity::Length:
                parsedValues.Length = static_cast<uint16_t>(udpToken->m_tokenValue);
                break;
            case enums::UPDHeaderTokenIdentity::ChecksumUDP:
                parsedValues.Checksum = static_cast<uint16_t>(udpToken->m_tokenValue);
                break;
            case enums::UPDHeaderTokenIdentity::UDPNone:
                return false;
        }
    }
    m_firstUnprocessed = headerTokenizer.GetPosition();
    return true;
}

bool DataParser::ParseMarketDataHeader(MarketDataHeaderValues& parsedValues)
{
    sbe_parser::MarketDataHeaderTokenizer headerTokenizer(m_data.Values, m_firstUnprocessed);
    while (!headerTokenizer.IsLastToken())
    {
        std::unique_ptr<BaseToken> token;
        if (!headerTokenizer.ReadToken(token) || !token)
        {
            return false;
        }
        sbe_parser::MarketDataHeaderToken* mdHeaderToken = dynamic_cast<sbe_parser::MarketDataHeaderToken*>(token.get());
        if (!mdHeaderToken)
        {
            return false;
        }
        switch (mdHeaderToken->m_tokenIdentity)
        {
            case enums::MarketDataTokenIdentity::MsgSeqNum:
            {
                parsedValues.MsgSeqNum = static_cast<uint32_t>(mdHeaderToken->m_bigValue);
                break;
            }
            case enums::MarketDataTokenIdentity::MsgSize:
            {
                parsedValues.MsgSize = static_cast<uint16_t>(mdHeaderToken->m_bigValue);
                break;
            }
            case enums::MarketDataTokenIdentity::MsgFlags:
            {
                parsedValues.MsgFlags = static_cast<uint16_t>(mdHeaderToken->m_bigValue);
                break;
            }
            case enums::MarketDataTokenIdentity::SendingTime:
            {
                parsedValues.SendingTime = mdHeaderToken->m_bigValue;
                break;
            }
            default:
            {
                return false;
            }
        }
    }
    m_firstUnprocessed = headerTokenizer.GetPosition();
    return true;
}
bool DataParser::ParseIncrementalPacketHeader(IncrementalPacketHeaderValues& parsedValues) {
    sbe_parser::IncrementalPacketHeaderTokenizer headerTokenizer(m_data.Values, m_firstUnprocessed);

    while (!headerTokenizer.IsLastToken()) {
        std::unique_ptr<BaseToken> token;
        if (!headerTokenizer.ReadToken(token) || !token) {
            return false;
        }

        auto* incToken = dynamic_cast<sbe_parser::IncrementalPacketHeaderToken*>(token.get());
        if (!incToken) {
            return false;
        }
        switch (incToken->m_tokenIdentity) {
            case enums::IncrementalPacketHeaderTokenIdentity::IncrementalPacketNone:
            {
                return false;
                break;
            }
            case enums::IncrementalPacketHeaderTokenIdentity::ExchangeTradingSessionID:
            {
                parsedValues.ExchangeTradingSessionID = static_cast<uint32_t>(incToken->m_bigValue);
                break;
            }
            case enums::IncrementalPacketHeaderTokenIdentity::TransactTime:
            {
                parsedValues.TransactTime = incToken->m_bigValue;
                break;
            }
        }
    }

    m_firstUnprocessed = headerTokenizer.GetPosition();
    return true;
}

} // namespace data_parser
} // namespace pcap_parser
