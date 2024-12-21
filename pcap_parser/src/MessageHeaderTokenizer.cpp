#include "data_parser/message/MessageHeaderTokenizer.h"

#include <iostream>
namespace pcap_parser
{
namespace data_parser
{
namespace sbe_parser
{

bool MessageHeaderTokenizer::ReadToken(std::unique_ptr<BaseToken> &token)
{
    enums::message::MessageHeaderTokenIdenity identity = static_cast<enums::message::MessageHeaderTokenIdenity>((static_cast<int>(m_lastTokenIdentity) + 1) % enums::message::MESSAGE_HEADER_TOKEN_SIZE); 

    if (identity == enums::message::MessageHeaderTokenIdenity::MessageHeaderNone)
    {
        return false;
    }
    // std::cout << " Kek " << identity << " " << int(m_values[m_position]) << " " << int(m_values[m_position + 1]) << std::endl;
    uint32_t value = 0;
    if (!GetKBytes(value, 2))
    {
        return false;
    }
    token = std::make_unique<MessageHeaderToken>(value, identity);
    m_lastTokenIdentity = identity;
    return true;
}

bool MessageHeaderTokenizer::IsLastToken() const
{   
    return m_lastTokenIdentity == enums::message::MessageHeaderTokenIdenity::Version;
}
void MessageHeaderTokenizer::ResetTerminal()
{
    m_lastTokenIdentity = enums::message::MessageHeaderTokenIdenity::MessageHeaderNone;
    m_position = m_startPosition;
}

} // namespace sbe_parser
} // namespace data_parser
} // namespace pcap_parser

