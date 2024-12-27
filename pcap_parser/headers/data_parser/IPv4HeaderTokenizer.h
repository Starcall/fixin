#pragma once
#include "vector"

#include "include/BaseToken.h"
#include "include/BaseTokenizer.h"
#include "include/Enums.h"


namespace pcap_parser
{
namespace data_parser
{

using Byte = unsigned char;


class IPv4HeaderToken : public BaseToken
{
public:
    IPv4HeaderToken() : BaseToken() {}
    IPv4HeaderToken(uint32_t value, enums::IPv4HeaderTokenIdentity tokenIdentity) :
        BaseToken(value),
        m_tokenIdentity(tokenIdentity)
    {}
    enums::IPv4HeaderTokenIdentity m_tokenIdentity = enums::IPv4HeaderTokenIdentity::IPv4None;
};

class IPv4HeaderTokenizer : public BaseTokenizer
{
public:
    IPv4HeaderTokenizer(std::vector<Byte> const& values, size_t position = 0) 
        : m_values(values), 
          m_position(position),
          m_startPosition(position)
    {
        m_lastTokenIdentity = enums::IPv4HeaderTokenIdentity::IPv4None;
        m_headerSize = 0;
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

    ~IPv4HeaderTokenizer() {};
private:
    // IPv4 always big endian
    bool GetKBytes(uint32_t& value, size_t k)
    {
        value = 0;
        if (k > 4 || m_values.size() < k + m_position)
        {
            return false;
        }
        while (k--)
        {
            value <<= 8;
            value += m_values[m_position];
            m_position++;
        }
        return true;
    }
    std::vector<Byte> const& m_values;
    size_t m_position, m_startPosition;
    uint8_t m_headerSize;

    enums::IPv4HeaderTokenIdentity m_lastTokenIdentity = enums::IPv4HeaderTokenIdentity::IPv4None;
};
    
} // namespace data_parser

    
} // namespace pcap_parser
