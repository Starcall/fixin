#include "data_parser/MarketDataHeaderTokenizer.h"

namespace pcap_parser
{
namespace data_parser
{
namespace sbe_parser
{

bool MarketDataHeaderTokenizer::ReadToken(std::unique_ptr<BaseToken> &token)
{
    enums::MarketDataTokenIdentity identity = static_cast<enums::MarketDataTokenIdentity>((static_cast<int>(m_lastTokenIdentity) + 1) % enums::MARKET_DATA_TOKEN_IDENTITY_SIZE); 

    if (identity == enums::MarketDataTokenIdentity::MarketDataNone)
    {
        return false;
    }
    size_t fieldSize = 2;
    if (identity == enums::MarketDataTokenIdentity::MsgSize) {
        fieldSize = 2;
    } else if (identity == enums::MarketDataTokenIdentity::MsgSeqNum) {
        fieldSize = 4;
    } else if (identity == enums::MarketDataTokenIdentity::MsgFlags) {
        fieldSize = 2;
    } else if (identity == enums::MarketDataTokenIdentity::SendingTime) {
        fieldSize = 8;
    } 

    uint64_t value = 0;
    if (!GetKBytes(value, fieldSize))
    {
        return false;
    }
    token = std::make_unique<MarketDataHeaderToken>(value, identity);
    m_lastTokenIdentity = identity;
    return true;
}

bool MarketDataHeaderTokenizer::IsLastToken() const
{   
    return m_lastTokenIdentity == enums::MarketDataTokenIdentity::MsgFlags;
}
void MarketDataHeaderTokenizer::ResetTerminal()
{
    m_lastTokenIdentity = enums::MarketDataTokenIdentity::MarketDataNone;
    m_position = m_startPosition;
}

} // namespace sbe_parser
} // namespace data_parser
} // namespace pcap_parser

