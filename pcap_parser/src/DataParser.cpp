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

std::string ipToDottedDecimal(uint32_t ip) {
    uint8_t b4 = (ip & 0xFF);
    uint8_t b3 = ((ip >> 8) & 0xFF);
    uint8_t b2 = ((ip >> 16) & 0xFF);
    uint8_t b1 = ((ip >> 24) & 0xFF);
    std::ostringstream oss;
    oss << (unsigned)b1 << "." << (unsigned)b2 << "." << (unsigned)b3 << "." << (unsigned)b4;
    return oss.str();
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
    os << "SourceIP: " << ipToDottedDecimal(ipv4.SourceIP) << "\n";
    os << "DestinationIp: " << ipToDottedDecimal(ipv4.DestinationIp) << "\n";
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

bool DataParser::ParseData(std::unique_ptr<BasicProtocolValues> &parsedValues)
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
                    EthernetIPv4UDPHeaderValues parsedUDPValues(parsedIPv4Values);    

                    UPDHeaderValues parsedUDPHeaderValues;
                    rc = ParseUDPHeader(parsedUDPHeaderValues);
                    if (!rc)
                    {
                        return false;
                    }       
                    parsedUDPValues.udpValues = parsedUDPHeaderValues;
                    parsedValues = std::make_unique<EthernetIPv4UDPHeaderValues>(parsedUDPValues);
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

} // namespace data_parser
} // namespace pcap_parser
