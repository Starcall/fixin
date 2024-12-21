#include "data_parser/UDPHeaderTokenizer.h"

namespace pcap_parser
{
namespace data_parser
{
    bool UDPHeaderTokenizer::ReadToken(std::unique_ptr<BaseToken>& token) 
    {
        enums::UPDHeaderTokenIdentity identity = static_cast<enums::UPDHeaderTokenIdentity>((static_cast<int>(m_lastTokenIdentity) + 1) % enums::UPD_HEADER_TOKEN_IDENTITY_SIZE);
        uint32_t value = 0;
        if (!GetKBytes(value, 2))
        {
            return false;
        }
        token = std::make_unique<UDPHeaderToken>(UDPHeaderToken(value, identity));
        m_lastTokenIdentity = identity;
        return true;
    };
    bool UDPHeaderTokenizer::IsLastToken() const 
    {
        return m_lastTokenIdentity == enums::UPDHeaderTokenIdentity::ChecksumUDP;
    };
    void UDPHeaderTokenizer::ResetTerminal() 
    {
        m_lastTokenIdentity = enums::UPDHeaderTokenIdentity::UDPNone;
        m_position = m_startPosition;
    };

} // namespace data_parser
} // namespace pcap_parser
