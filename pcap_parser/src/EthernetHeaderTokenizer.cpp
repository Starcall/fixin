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
    if (identity == enums::EthernetHeaderTokenIdentity::DestinationMac || identity == enums::EthernetHeaderTokenIdentity::SourceMac)
    {
        // ensure we are fitting into values
        if (static_cast<int>(m_values.size()) - m_position >= 6)
        {
            std::copy(m_values.begin() + m_position, m_values.begin() + m_position + 6, value.begin());
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
        uint32_t value = 0;
        if (static_cast<int>(m_values.size()) - m_position >= 2)
        {
            value = (static_cast<uint16_t>(m_values[m_position]) << 8) + m_values[m_position + 1];
        }
        else
        {
            return false;
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
    m_position = 0;
}

} // namespace data_parser
} // namespace pcap_parser
