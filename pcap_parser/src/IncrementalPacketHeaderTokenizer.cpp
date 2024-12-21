#include "data_parser/IncrementalPacketHeaderTokenizer.h"

namespace pcap_parser 
{
namespace data_parser
{
namespace sbe_parser
{


IncrementalPacketHeaderTokenizer::IncrementalPacketHeaderTokenizer(std::vector<Byte> const& values, size_t position)
    : m_values(values), m_position(position), m_startPosition(position) {
    m_lastTokenIdentity = enums::IncrementalPacketHeaderTokenIdentity::IncrementalPacketNone;
}

bool IncrementalPacketHeaderTokenizer::ReadToken(std::unique_ptr<BaseToken>& token) {
    enums::IncrementalPacketHeaderTokenIdentity identity =
        static_cast<enums::IncrementalPacketHeaderTokenIdentity>(
            (static_cast<int>(m_lastTokenIdentity) + 1) % enums::INCREMENTAL_PACKET_HEADER_TOKEN_IDENTITY_SIZE);

    if (identity == enums::IncrementalPacketHeaderTokenIdentity::IncrementalPacketNone) {
        return false;
    }
    size_t fieldSize = 4;
    if (identity == enums::IncrementalPacketHeaderTokenIdentity::TransactTime) {
        fieldSize = 8;
    }
    uint64_t value = 0;
    if (!GetKBytes(value, fieldSize)) {
        return false;
    }

    token = std::make_unique<IncrementalPacketHeaderToken>(value, identity);
    m_lastTokenIdentity = identity;
    return true;
}

bool IncrementalPacketHeaderTokenizer::IsLastToken() const {
    return m_lastTokenIdentity == enums::IncrementalPacketHeaderTokenIdentity::ExchangeTradingSessionID;
}

void IncrementalPacketHeaderTokenizer::ResetTerminal() {
    m_lastTokenIdentity = enums::IncrementalPacketHeaderTokenIdentity::IncrementalPacketNone;
    m_position = m_startPosition;
}

IncrementalPacketHeaderTokenizer::~IncrementalPacketHeaderTokenizer() {}

} // namespace pcap_parser
} // namespace sbe_parser
} // namespace data_parser
