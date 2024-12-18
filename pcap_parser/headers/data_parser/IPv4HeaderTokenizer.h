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
    IPv4HeaderTokenizer(std::vector<uint32_t> const& values, std::vector<Byte> const& tail, size_t position = 0) 
        : m_values(values), 
          m_tail(tail),
          m_position(position),
          m_startPosition(position)
    {
        m_rawData = reinterpret_cast<const uint8_t*>(m_values.data());
        m_lastTokenIdentity = enums::IPv4HeaderTokenIdentity::IPv4None;
        m_headerSize = 0;
    }
    /* BaseTokenizer methods */
    bool ReadToken(std::unique_ptr<BaseToken>& token) override;
    bool IsLastToken() const override;
    void ResetTerminal() override;
    /**/
    ~IPv4HeaderTokenizer() {};
private:
    bool Get2Bytes(uint32_t& value)
    {
        int bytesLeft = static_cast<int>(m_values.size() * sizeof(uint32_t)) - m_position;
        int tailPosition = m_position - static_cast<int>(m_values.size() * sizeof(uint32_t));
        if (bytesLeft > 1)
        {
            if (!m_rawData)
            {
                return false;
            }
            value = (static_cast<uint16_t>(m_rawData[m_position]) << 8) + m_rawData[m_position + 1];
        }
        else if (bytesLeft == 1)
        {
            if (!m_rawData || !m_tail.size())
            {
                return false;
            }
            value = (static_cast<uint16_t>(m_rawData[m_position] << 8)) + m_tail[0];
        }
        else
        {
            if (tailPosition + 1 >= static_cast<int>(m_tail.size()))
            {
                return false;
            }
            value = (static_cast<uint16_t>(m_tail[tailPosition] << 8)) + m_tail[tailPosition + 1];
        }
        return true;
    }
    const uint8_t* m_rawData; 
    std::vector<uint32_t> const& m_values;
    std::vector<Byte> const& m_tail;
    size_t m_position, m_startPosition;
    uint8_t m_headerSize;

    enums::IPv4HeaderTokenIdentity m_lastTokenIdentity = enums::IPv4HeaderTokenIdentity::IPv4None;
};
    
} // namespace data_parser

    
} // namespace pcap_parser
