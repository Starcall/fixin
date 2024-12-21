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
using Byte = unsigned char;

class MessageHeaderToken : public BaseToken
{
public:
    MessageHeaderToken() : BaseToken() {}
    MessageHeaderToken(uint32_t value, enums::message::MessageHeaderTokenIdenity tokenIdentity) :
        BaseToken(value),
        m_tokenIdentity(tokenIdentity)
    {}
    enums::message::MessageHeaderTokenIdenity m_tokenIdentity = enums::message::MessageHeaderTokenIdenity::MessageHeaderNone;
};

class MessageHeaderTokenizer : public BaseTokenizer
{
public:
    MessageHeaderTokenizer(std::vector<Byte> const& values, size_t position = 0) 
        : m_values(values), 
          m_position(position),
          m_startPosition(position)
    {
        m_lastTokenIdentity = enums::message::MessageHeaderTokenIdenity::MessageHeaderNone;
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

    ~MessageHeaderTokenizer() {};
private:
    // Message little endian
    bool GetKBytes(uint32_t& value, size_t k)
    {
        value = 0;
        if (k > 4 || (static_cast<int>(m_values.size()) - m_position < k)) 
        {
            return false;
        }
        for (size_t i = 0; i < k; i++)
        {
            value |= static_cast<uint32_t>(m_values[m_position]) << (8 * i);
            m_position++;
        }
        return true;
    }
    std::vector<Byte> const& m_values;
    size_t m_position, m_startPosition;

    enums::message::MessageHeaderTokenIdenity m_lastTokenIdentity = enums::message::MessageHeaderTokenIdenity::MessageHeaderNone;
};

} // namespace sbe_parser
} // namespace data_parser
} // namespace pcap_parser
