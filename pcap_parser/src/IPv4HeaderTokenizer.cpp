#include "data_parser/IPv4HeaderTokenizer.h"

namespace pcap_parser
{
namespace data_parser
{

bool IPv4HeaderTokenizer::ReadToken(std::unique_ptr<BaseToken> &token)
{
    enums::IPv4HeaderTokenIdentity identity = static_cast<enums::IPv4HeaderTokenIdentity>((static_cast<int>(m_lastTokenIdentity) + 1) % enums::IPV4_HEADER_TOKEN_IDENTITY_SIZE);
    // Number of bytes we did not process in mvalues
    uint32_t value = 0;
                
    switch (identity)
    {
        case enums::IPv4HeaderTokenIdentity::IPv4None:
        {
            return false;
            break;
        }
        case enums::IPv4HeaderTokenIdentity::Version:
        {
            // since IHL and version stored in one byte we should not move position 
            auto rc = GetKBytes(value, 1);
            if (!rc)
            {
                return false;
            }
            value >>= 4;
            m_position--;
            break;
        }
        case enums::IPv4HeaderTokenIdentity::IHL:
        {            
            auto rc = GetKBytes(value, 1);
            if (!rc)
            {
                return false;
            }
            value &= 0xF;
            m_headerSize = value * 4;
            break;
        }
        case enums::IPv4HeaderTokenIdentity::TypeOfService:
        {
            auto rc = GetKBytes(value, 1);
            if (!rc)
            {
                return false;
            }
            break;
        }
        case enums::IPv4HeaderTokenIdentity::TotalLength:
        {
            auto rc = GetKBytes(value, 2);
            if (!rc)
            {
                return false;
            }
            break;
        }
        case enums::IPv4HeaderTokenIdentity::Identification:
        {
            auto rc = GetKBytes(value, 2);
            if (!rc)
            {
                return false;
            }
            break;
        }
        case enums::IPv4HeaderTokenIdentity::Flags:
        {
            // do not move position since we are still have data to parse in that byte
            auto rc = GetKBytes(value, 1);
            if (!rc)
            {
                return false;
            }
            value >>= 5;
            m_position--;
            break;
        }
        case enums::IPv4HeaderTokenIdentity::FragmentOffset:
        {
            auto rc = GetKBytes(value, 2);
            if (!rc)
            {
                return false;
            }
            value &= 0x1FFF;
            break;
        }
        case enums::IPv4HeaderTokenIdentity::TTL:
        {
            auto rc = GetKBytes(value, 1);
            if (!rc)
            {
                return false;
            }
            break;
        }
        case enums::IPv4HeaderTokenIdentity::Protocol:
        {
            auto rc = GetKBytes(value, 1);
            if (!rc)
            {
                return false;
            }
            break;
        }
        case enums::IPv4HeaderTokenIdentity::Checksum:
        {
            auto rc = GetKBytes(value, 2);
            if (!rc)
            {
                return false;
            }
            break;
        }
        case enums::IPv4HeaderTokenIdentity::SourceIP:
        {
            auto rc = GetKBytes(value, 4);
            if (!rc)
            {
                return false;
            }
            break;
        }
        case enums::IPv4HeaderTokenIdentity::DestinationIp:
        {
            auto rc = GetKBytes(value, 4);
            if (!rc)
            {
                return false;
            }
            break;
        }
        case enums::IPv4HeaderTokenIdentity::Options:
        {
            // I do not want to store it for now, just skip 
            if (m_headerSize > 20) 
            {
                m_position += m_headerSize - 20;
            }
            if (m_position > m_values.size())
            {
                return false;
            }
            value = 0;
            break;
        }
    }
    m_lastTokenIdentity = identity;
    token = std::make_unique<IPv4HeaderToken>(IPv4HeaderToken(value, identity));
    return true;
}
bool IPv4HeaderTokenizer::IsLastToken() const
{
    return m_lastTokenIdentity == enums::IPv4HeaderTokenIdentity::Options;
}
void IPv4HeaderTokenizer::ResetTerminal()
{
    m_lastTokenIdentity = enums::IPv4HeaderTokenIdentity::IPv4None;
    m_position = m_startPosition;
    m_headerSize = 0;
    return;
}

} // namespace data_parser
} // namespace pcap_parser
