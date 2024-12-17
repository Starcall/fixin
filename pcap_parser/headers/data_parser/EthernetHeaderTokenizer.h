#pragma once

#include "include/BaseTokenizer.h"
#include "include/BaseToken.h"
#include "include/Enums.h"

#include <array>
#include "vector"
#include "iostream"

namespace pcap_parser
{
namespace data_parser
{

using Byte = unsigned char;


class EthernetHeaderToken : public BaseToken
{
public:
    EthernetHeaderToken() : BaseToken() {}
    EthernetHeaderToken(uint32_t value, enums::EthernetTokenIdentity tokenIdentity) :
        BaseToken(value),
        m_tokenIdentity(tokenIdentity)
    {
        m_bigTokenValue.fill(0);
    }
    EthernetHeaderToken(std::array<Byte, 6> tokenValue, enums::EthernetTokenIdentity tokenIdentity) : 
        BaseToken(0),
        m_bigTokenValue(tokenValue),
        m_tokenIdentity(tokenIdentity)
    {}
    std::array<Byte, 6> m_bigTokenValue;
    enums::EthernetTokenIdentity m_tokenIdentity = enums::EthernetTokenIdentity::EthernetNone;
};


class EthernetHeaderTokenizer : public BaseTokenizer
{
public:
    EthernetHeaderTokenizer(std::vector<uint32_t> const& values, std::vector<Byte> const& tail) : m_values(values), m_tail(tail)
    {
        m_rawData = reinterpret_cast<const uint8_t*>(m_values.data());
        m_position = 0;
        m_lastTokenIdentity = enums::EthernetTokenIdentity::EthernetNone;
    }
    /*
    * BaseTokenizer methods
    */
    bool ReadToken(std::unique_ptr<BaseToken>& token) override;
    bool IsLastToken() const override;
    void ResetTerminal() override;
    /**/

    ~EthernetHeaderTokenizer() {}
private:
    const uint8_t* m_rawData; 
    std::vector<uint32_t> const& m_values;
    std::vector<Byte> const& m_tail;
    size_t m_position;
    
    enums::EthernetTokenIdentity m_lastTokenIdentity = enums::EthernetTokenIdentity::EthernetNone;
};

} // namespace data_parser   
} // namespace pcap_parser
