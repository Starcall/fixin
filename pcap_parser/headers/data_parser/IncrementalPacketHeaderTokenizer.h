#pragma once

#include "include/BaseTokenizer.h"
#include "include/BaseToken.h"
#include "include/Enums.h"

#include "vector"

namespace pcap_parser 
{
namespace data_parser
{
namespace sbe_parser
{

class IncrementalPacketHeaderToken : public BaseToken {
public:
    IncrementalPacketHeaderToken() : BaseToken() {}
    IncrementalPacketHeaderToken(uint32_t value, enums::IncrementalPacketHeaderTokenIdentity identity)
        : BaseToken(value), 
          m_tokenIdentity(identity),
          m_bigValue(value) 
    {}
    IncrementalPacketHeaderToken(uint64_t value, enums::IncrementalPacketHeaderTokenIdentity identity)
        : BaseToken(0), 
          m_tokenIdentity(identity),
          m_bigValue(value) 
    {}
    enums::IncrementalPacketHeaderTokenIdentity m_tokenIdentity = enums::IncrementalPacketHeaderTokenIdentity::IncrementalPacketNone;
    uint64_t m_bigValue;
};

class IncrementalPacketHeaderTokenizer : public BaseTokenizer {
public:
    IncrementalPacketHeaderTokenizer(std::vector<Byte> const& values, size_t position = 0);
    /* BaseTokenizer methods */
    bool ReadToken(std::unique_ptr<BaseToken>& token) override;
    bool IsLastToken() const override;
    void ResetTerminal() override;
    /**/

    /*
    * get first byte that was not processed by tokenizer
    */
    size_t GetPosition() const
    {
        return m_position;
    }
    ~IncrementalPacketHeaderTokenizer();

private:
    // Packet Little Endian
    bool GetKBytes(uint64_t& value, size_t k)
    {
        value = 0;
        if (k > 8 || (static_cast<int>(m_values.size()) - m_position < k)) 
        {
            return false;
        }
        for (size_t i = 0; i < k; i++)
        {
            value |= static_cast<uint64_t>(m_values[m_position]) << (8 * i);
            m_position++;
        }
        return true;
    }
    std::vector<Byte> const& m_values;
    size_t m_position, m_startPosition;
    enums::IncrementalPacketHeaderTokenIdentity m_lastTokenIdentity =
        enums::IncrementalPacketHeaderTokenIdentity::IncrementalPacketNone;
};

} // namespace pcap_parser

} // namespace sbe_parser
} // namespace data_parser
