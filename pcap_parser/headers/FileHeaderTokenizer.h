#pragma once

#include "include/Enums.h"
#include "include/Tokenizer.h"


namespace pcap_parser
{

/*
* Consider one token as a full raw data in this case
*/
class FileHeaderToken : public BaseToken
{
public:
    FileHeaderToken() : BaseToken() {}
    FileHeaderToken(uint32_t tokenValue, enums::HeaderTokenIdentity tokenIdentity) : 
        BaseToken(tokenValue),
        m_tokenIdentity(tokenIdentity)
    {}
    enums::HeaderTokenIdentity m_tokenIdentity = enums::HeaderTokenIdentity::HeaderNone;
};

class FileHeaderTokenizer : public Tokenizer
{

public:
    FileHeaderTokenizer() : Tokenizer()
    {
        m_lastTokenIdentity = enums::HeaderTokenIdentity::HeaderNone;
    }
    FileHeaderTokenizer(std::shared_ptr<std::ifstream> fileStream);
    FileHeaderTokenizer(FileHeaderTokenizer&& other) noexcept : Tokenizer(std::move(other))
    {
        m_lastTokenIdentity = other.m_lastTokenIdentity;
    }
    FileHeaderTokenizer& operator=(FileHeaderTokenizer&& other) noexcept
    {
        if (this != &other)
        {
            Tokenizer::operator=(std::move(other));
            m_lastTokenIdentity = other.m_lastTokenIdentity;
        }
        return *this;
    }
    /*
    * BaseTokenizer methods
    */
    bool ReadToken(std::unique_ptr<BaseToken>& token) override;
    bool IsLastToken() const override;
    void ResetTerminal() override;
    /**/

    ~FileHeaderTokenizer();
private:
    enums::HeaderTokenIdentity m_lastTokenIdentity = enums::HeaderTokenIdentity::HeaderNone;
};
    
} // namespace pcap_parser
