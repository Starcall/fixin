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
    FileHeaderTokenizer(std::shared_ptr<std::ifstream> fileStream);

    /*
    * Tokenizer methods
    */
    bool ReadToken(std::unique_ptr<BaseToken>& token) override;
    bool IsLastToken() const override;
    /**/
    HeaderTokenIdentity m_lastTokenIdentity = HeaderTokenIdentity::HeaderNone;

    ~FileHeaderTokenizer();
};
    
} // namespace pcap_parser
