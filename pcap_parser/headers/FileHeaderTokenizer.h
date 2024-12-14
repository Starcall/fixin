#pragma once

#include "Tokenizer.h"

namespace pcap_parser
{

const size_t HEADER_TOKEN_IDENTITY_SIZE = 7;
enum HeaderTokenIdentity
{
    MagicNumber,
    Versions,
    Reserved1,
    Reserved2,
    SnapLen,
    LinkType,
    HeaderNone
};

/*
* Consider one token as a full raw data in this case
*/
class FileHeaderToken : public BaseToken
{
public:
    FileHeaderToken() : BaseToken() {}
    FileHeaderToken(uint32_t tokenValue, HeaderTokenIdentity tokenIdentity) : 
        BaseToken(tokenValue),
        m_tokenIdentity(tokenIdentity)
    {}
    HeaderTokenIdentity m_tokenIdentity = HeaderTokenIdentity::HeaderNone;
};

class FileHeaderTokenizer : public Tokenizer
{

public:
    FileHeaderTokenizer() : Tokenizer()
    {
        m_lastTokenIdentity = HeaderTokenIdentity::HeaderNone;
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
    * Tokenizer methods
    */
    bool ReadToken(std::unique_ptr<BaseToken>& token) override;
    bool IsLastToken() const override;
    /**/

    ~FileHeaderTokenizer();
private:
    HeaderTokenIdentity m_lastTokenIdentity = HeaderTokenIdentity::HeaderNone;
};
    
} // namespace pcap_parser
