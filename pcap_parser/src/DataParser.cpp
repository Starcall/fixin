#include "data_parser/DataParser.h"

#include "iostream"
#include <iomanip> 

namespace pcap_parser
{
namespace data_parser
{

std::ostream& operator<<(std::ostream &os, EthernetDataValues const& data)
{
    os << "Type: " << static_cast<int>(data.Type) << "\n";

    os << "Destination MAC: ";
    for (size_t i = 0; i < data.DestinationMac.size(); ++i) {
        os << std::hex << std::setw(2) << std::setfill('0') 
           << static_cast<int>(data.DestinationMac[i]);
        if (i < data.DestinationMac.size() - 1) {
            os << ":";
        }
    }
    os << "\n";

    os << "Source MAC: ";
    for (size_t i = 0; i < data.SourceMac.size(); ++i) {
        os << std::hex << std::setw(2) << std::setfill('0') 
           << static_cast<int>(data.SourceMac[i]);
        if (i < data.SourceMac.size() - 1) {
            os << ":";
        }
    }
    os << "\n";

    os << "Payload: ";
    for (const auto& byte : data.Payload) {
        os << std::hex << std::setw(2) << std::setfill('0') 
           << static_cast<int>(byte) << " ";
    }
    os << "\n";

    // Return the stream to allow chaining (e.g., std::cout << data << ... )
    return os;
}

bool DataParser::ParseData(std::unique_ptr<BasicProtocolValues> &parsedValues)
{
    // TODO log
    switch (m_fileMetadata.LinkType)
    {
        case 1:
        {
            EthernetDataValues parsedDataValues;
            auto rc = ParseEthernetProtocol(parsedDataValues);
            if (!rc)
            {
                return false;
            }
            // Parse data
            parsedValues = std::make_unique<EthernetDataValues>(parsedDataValues);
            return true;
        }
        default:
        {
            return false;
        }
    }

}
bool DataParser::ParseEthernetProtocol(EthernetDataValues &parsedValues)
{
    // TODO add log
    EthernetHeaderTokenizer headerTokenizer = EthernetHeaderTokenizer(m_data.values, m_data.tail);
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
            case enums::EthernetTokenIdentity::DestinationMac:
            {
                // memcpy?
                parsedValues.DestinationMac = ethernetHeaderToken->m_bigTokenValue;
                break;
            }
            case enums::EthernetTokenIdentity::SourceMac:
            {
                //ditto
                parsedValues.SourceMac = ethernetHeaderToken->m_bigTokenValue;
                break;
            }
            case enums::EthernetTokenIdentity::Type:
            {
                parsedValues.Type = static_cast<uint16_t>(ethernetHeaderToken->m_tokenValue & 0xFFFF);
                break;
            }
            case enums::EthernetTokenIdentity::EthernetNone:
            {
                return false;
                break;
            }
        }
    }
    return true;
}

} // namespace data_parser
} // namespace pcap_parser
