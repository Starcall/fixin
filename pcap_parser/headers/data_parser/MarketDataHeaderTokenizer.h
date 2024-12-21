#pragma once

#include "include/BaseToken.h"
#include "include/BaseTokenizer.h"
#include "include/Enums.h"

#include <vector>

namespace pcap_parser
{
namespace data_parser
{
namespace sbe_parser
{

using Byte = unsigned char;


class MarketDataHeaderToken : public BaseToken
{
public:
    MarketDataHeaderToken() : BaseToken() {}
    MarketDataHeaderToken(uint32_t value, enums::MarketDataTokenIdentity tokenIdentity) :
        BaseToken(value),
        m_tokenIdentity(tokenIdentity),
        m_bigValue(value)
    {}
    MarketDataHeaderToken(uint64_t value, enums::MarketDataTokenIdentity tokenIdentity) :
        BaseToken(0),
        m_tokenIdentity(tokenIdentity),
        m_bigValue(value)
    {}
    enums::MarketDataTokenIdentity m_tokenIdentity = enums::MarketDataTokenIdentity::MarketDataNone;
    uint64_t m_bigValue;
};


class MarketDataHeaderTokenizer : public BaseTokenizer
{
public:
    MarketDataHeaderTokenizer(std::vector<Byte> const& values, size_t position = 0) 
        : m_values(values), 
          m_position(position),
          m_startPosition(position)
    {
        m_lastTokenIdentity = enums::MarketDataTokenIdentity::MarketDataNone;
    }
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

    ~MarketDataHeaderTokenizer() {};
private:
    // MarketData Little Endian
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

    enums::MarketDataTokenIdentity m_lastTokenIdentity = enums::MarketDataTokenIdentity::MarketDataNone;
};

} // namespace sbe_parser
} // namespace data_parser
} // namespace pcap_parser
