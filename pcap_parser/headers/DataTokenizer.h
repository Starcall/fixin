#pragma once
#include "BaseToken.h"
#include "Tokenizer.h"

namespace pcap_parser
{

class DataToken : public BaseToken
{
public:
    DataToken() : BaseToken() {}
    DataToken(uint32_t tokenValue)
    {
        m_4BytesValues.emplace_back(tokenValue);
    }
    DataToken(std::vector<BaseToken> const& values, std::vector<Byte> const& tail) : m_4BytesValues(values), m_tail(tail)
    {}
    DataToken(DataToken const& otherToken) : m_4BytesValues(otherToken.m_4BytesValues), m_tail(otherToken.m_tail)
    {}
    DataToken(DataToken &&otherToken)
    {
        m_4BytesValues = std::move(otherToken.m_4BytesValues);
        m_tail = std::move(otherToken.m_tail);
    }
    // we assume here that data is not that big in our case so we can store it in memory 
    std::vector<BaseToken> m_4BytesValues;
    std::vector<Byte> m_tail;
};

class DataTokenizer : public Tokenizer
{
public:
    DataTokenizer() : Tokenizer()
    {
        m_length = 0;
    }
    DataTokenizer(std::shared_ptr<std::ifstream> fileStream);
    DataTokenizer(DataTokenizer&& other) noexcept : Tokenizer(std::move(other))
    {
        m_length = other.m_length;
    }
    DataTokenizer& operator=(DataTokenizer&& other) noexcept
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
    * Tokenizer methods
    */
    bool ReadToken(std::unique_ptr<BaseToken>& token) override;
    bool IsLastToken() const override;
    void ResetTerminal() override;
    /**/
    ~DataTokenizer();  
private:
    size_t m_length = 0;
    bool m_isTerminal = false;
};

} // namespace pcap_parser
