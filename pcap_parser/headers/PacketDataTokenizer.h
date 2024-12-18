#pragma once
#include "include/BaseToken.h"
#include "include/Tokenizer.h"

namespace pcap_parser
{

class PacketDataToken : public BaseToken
{
public:
    PacketDataToken() : BaseToken() {}
    PacketDataToken(uint32_t tokenValue)
    {
        m_values.emplace_back(tokenValue);
    }
    PacketDataToken(std::vector<Byte> const& values) : m_values(values)
    {}
    PacketDataToken(PacketDataToken const& otherToken) : m_values(otherToken.m_values)
    {}
    PacketDataToken(PacketDataToken &&otherToken)
    {
        m_values = std::move(otherToken.m_values);
    }
    // we assume here that data is not that big in our case so we can store it in memory 
    std::vector<Byte> m_values;
};

class PacketDataTokenizer : public Tokenizer
{
public:
    PacketDataTokenizer() : Tokenizer()
    {
        m_length = 0;
    }
    PacketDataTokenizer(std::shared_ptr<std::ifstream> fileStream);
    PacketDataTokenizer(PacketDataTokenizer&& other) noexcept : Tokenizer(std::move(other))
    {
        m_length = other.m_length;
    }
    PacketDataTokenizer& operator=(PacketDataTokenizer&& other) noexcept
    {
        if (this != &other)
        {
            Tokenizer::operator=(std::move(other));
            m_length = other.m_length;
        }
        return *this;
    }
    /*
    * Sets the length of data to tokenize
    * @param lengthInBytes - size of the raw data to read
    * must be specified before call ReadToken()
    */
    void SetDataLength(size_t lengthInBytes);

    /*
    * BaseTokenizer methods
    */
    bool ReadToken(std::unique_ptr<BaseToken>& token) override;
    bool IsLastToken() const override;
    void ResetTerminal() override;
    /**/

    ~PacketDataTokenizer();  
private:
    size_t m_length = 0;
    bool m_isTerminal = false;
};

} // namespace pcap_parser
