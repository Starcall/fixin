#include "data_parser/EthernetHeaderTokenizer.h"
#include "iostream"
namespace pcap_parser
{
namespace data_parser
{

bool EthernetHeaderTokenizer::ReadToken(std::unique_ptr<BaseToken> &token)
{
    std::array<uint8_t, 6> value;
    enums::EthernetHeaderTokenIdentity identity = static_cast<enums::EthernetHeaderTokenIdentity>((static_cast<int>(m_lastTokenIdentity) + 1) % enums::ETHERNET_HEADER_TOKEN_IDENTITY_SIZE);
    
    // Number of bytes we did not process in mvalues
    int bytesLeft = static_cast<int>(m_values.size() * sizeof(uint32_t)) - m_position;
    bytesLeft = std::max(0, bytesLeft);
    auto tailPosition = m_position - static_cast<int>(m_values.size() * sizeof(uint32_t));
    if (identity == enums::EthernetHeaderTokenIdentity::DestinationMac || identity == enums::EthernetHeaderTokenIdentity::SourceMac)
    {
        if (!m_rawData)
        {
            return false;
        }
        // ensure we are fitting into values
        if (bytesLeft >= 6)
        {
            std::copy(m_rawData + m_position, m_rawData + m_position + 6, value.begin());
        }
        // ensure we are fitting into tail
        else if (6 - bytesLeft <= static_cast<int>(m_tail.size()))
        {
            std::copy(m_rawData + m_position, m_rawData + m_position + bytesLeft, value.begin());
            for (int i = 0; i < 6 - bytesLeft; i++)
            {
                value[i + bytesLeft + i] = m_tail[i];
            }
        }
        else
        {
            return false;
        }
        m_position += 6;
        token = std::make_unique<EthernetHeaderToken>(EthernetHeaderToken(value, identity));
    }
    else
    {
        // Cringe... It also not possible in correct file
        if (!m_rawData && m_tail.size() < 2)
        {
            return false;
        }
        uint32_t value = 0;
        if (bytesLeft >= 2)
        {
            if (!m_rawData)
            {
                return false;
            }
            value = (m_rawData[m_position] << 8) + m_rawData[m_position + 1];
        }
        else if (bytesLeft == 1)
        {
            if (!m_rawData)
            {
                return false;
            }
            if (!m_tail.size())
            {
                return false;
            }
            value = (m_rawData[m_position] << 8) + m_tail[0];
        }
        else
        {
            if (tailPosition + 1 >= m_tail.size())
            {
                return false;
            }
            value = (m_tail[tailPosition] << 8) + m_tail[tailPosition + 1];
            
        }
        m_position += 2;
        token = std::make_unique<EthernetHeaderToken>(EthernetHeaderToken(value, identity));
    }
    m_lastTokenIdentity = identity;
    return true;
}

bool EthernetHeaderTokenizer::IsLastToken() const
{
    return m_lastTokenIdentity == enums::EthernetHeaderTokenIdentity::Type;
}

void EthernetHeaderTokenizer::ResetTerminal()
{
    m_lastTokenIdentity = enums::EthernetHeaderTokenIdentity::EthernetNone;
    m_rawData = nullptr;
    m_position = 0;
}

} // namespace data_parser
} // namespace pcap_parser
