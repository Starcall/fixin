#pragma once
#include "include/BaseToken.h"
#include "include/BaseTokenizer.h"
#include "include/Enums.h"
#include "include/Values.h"

namespace pcap_parser
{
namespace data_parser
{

using Byte = unsigned char;

class UDPHeaderToken : public BaseToken
{
public:
    UDPHeaderToken() : BaseToken() {}
    UDPHeaderToken(uint32_t value, enums::UPDHeaderTokenIdentity tokenIdentity) :
        BaseToken(value),
        m_tokenIdentity(tokenIdentity)
    {}
    enums::UPDHeaderTokenIdentity m_tokenIdentity = enums::UPDHeaderTokenIdentity::UDPNone;
};

class UDPHeaderTokenizer : public BaseTokenizer
{
public:
    UDPHeaderTokenizer(std::vector<Byte> const& values, size_t position = 0) 
        : m_values(values), 
          m_position(position),
          m_startPosition(position)
    {
        m_lastTokenIdentity = enums::UPDHeaderTokenIdentity::UDPNone;
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

    ~UDPHeaderTokenizer() {};
private:
    // UDP always big endian
    // duplicate code could be removed
    bool GetKBytes(uint32_t& value, size_t k)
    {
        value = 0;
        if (k > 4 || (static_cast<int>(m_values.size()) - m_position < k)) 
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

    enums::UPDHeaderTokenIdentity m_lastTokenIdentity = enums::UPDHeaderTokenIdentity::UDPNone;
};

    
} // namespace data_parser
} // namespace pcap_parser
