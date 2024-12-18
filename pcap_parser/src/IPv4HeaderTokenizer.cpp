#include "data_parser/IPv4HeaderTokenizer.h"

namespace pcap_parser
{
namespace data_parser
{

bool IPv4HeaderTokenizer::ReadToken(std::unique_ptr<BaseToken> &token)
{
    enums::IPv4HeaderTokenIdentity identity = static_cast<enums::IPv4HeaderTokenIdentity>((static_cast<int>(m_lastTokenIdentity) + 1) % enums::IPV4_HEADER_TOKEN_IDENTITY_SIZE);
    // Number of bytes we did not process in mvalues
    int bytesLeft = static_cast<int>(m_values.size() * sizeof(uint32_t)) - m_position;
    int tailPosition = m_position - static_cast<int>(m_values.size() * sizeof(uint32_t));
    bytesLeft = std::max(0, bytesLeft);
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
            if (bytesLeft)
            {
                if (!m_rawData)
                {
                    return false;
                }
                value = m_rawData[m_position] >> 4;
            }
            else
            {
                value = m_tail[tailPosition] >> 4;
            }
            break;
        }
        case enums::IPv4HeaderTokenIdentity::IHL:
        {            
            if (bytesLeft)
            {
                if (!m_rawData)
                {
                    return false;
                }
                value = (m_rawData[m_position] & 0xF);
            }
            else
            {
                value = (m_tail[tailPosition] & 0xF);
            }
            m_headerSize = value * 4;
            m_position++;
            break;
        }
        case enums::IPv4HeaderTokenIdentity::TypeOfService:
        {
            if (bytesLeft)
            {
                if (!m_rawData)
                {
                    return false;
                }
                value = m_rawData[m_position];
            }
            else
            {
                value = m_tail[tailPosition];
            }
            m_position++;
            break;
        }
        case enums::IPv4HeaderTokenIdentity::TotalLength:
        {
            auto rc = Get2Bytes(value);
            if (!rc)
            {
                return false;
            }
            m_position += 2;
            break;
        }
        case enums::IPv4HeaderTokenIdentity::Identification:
        {
            auto rc = Get2Bytes(value);
            if (!rc)
            {
                return false;
            }
            m_position += 2;
            break;
        }
        case enums::IPv4HeaderTokenIdentity::Flags:
        {
            // do not move position since we are still have data to parse in that byte
            if (bytesLeft)
            {
                if (!m_rawData)
                {
                    return false;
                }
                value = m_rawData[m_position] >> 5;
            }
            else
            {
                value = m_tail[tailPosition] >> 5;
            }
            break;
        }
        case enums::IPv4HeaderTokenIdentity::FragmentOffset:
        {
            auto rc = Get2Bytes(value);
            if (!rc)
            {
                return false;
            }
            value &= 0x1FFF;
            m_position += 2;
            break;
        }
        case enums::IPv4HeaderTokenIdentity::TTL:
        {
            if (bytesLeft)
            {
                if (!m_rawData)
                {
                    return false;
                }
                value = m_rawData[m_position];
            }
            else
            {
                value = m_tail[tailPosition];
            }
            m_position++;
            break;
        }
        case enums::IPv4HeaderTokenIdentity::Protocol:
        {
            if (bytesLeft)
            {
                if (!m_rawData)
                {
                    return false;
                }
                value = m_rawData[m_position];
            }
            else
            {
                value = m_tail[tailPosition];
            }
            m_position++;
            break;
        }
        case enums::IPv4HeaderTokenIdentity::Checksum:
        {
            auto rc = Get2Bytes(value);
            if (!rc)
            {
                return false;
            }
            m_position += 2;
            break;
        }
        case enums::IPv4HeaderTokenIdentity::SourceIP:
        {
            uint32_t leftValue, rightValue = 0;
            auto rc = Get2Bytes(leftValue);
            if (!rc)
            {
                return false;
            }
            rc = Get2Bytes(rightValue);
            if (!rc)
            {
                return false;
            }
            value = (leftValue << 16) + rightValue;
            m_position += 4;
            break;
        }
        case enums::IPv4HeaderTokenIdentity::DestinationIp:
        {
            uint32_t leftValue, rightValue = 0;
            auto rc = Get2Bytes(leftValue);
            if (!rc)
            {
                return false;
            }
            rc = Get2Bytes(rightValue);
            if (!rc)
            {
                return false;
            }
            value = (leftValue << 16) + rightValue;
            m_position += 4;
            break;
        }
        case enums::IPv4HeaderTokenIdentity::Options:
        {
            // I do not want to store it for now, just skip 
            if (m_headerSize > 20) 
            {
                m_position += m_headerSize - 20;
            }
            if (m_position > static_cast<int>(m_values.size() * sizeof(uint32_t)) + m_tail.size() + 1)
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
    m_rawData = nullptr;
    m_position = m_startPosition;
    m_headerSize = 0;
    return;
}
}

// namespace data_parser
} // namespace pcap_parser
