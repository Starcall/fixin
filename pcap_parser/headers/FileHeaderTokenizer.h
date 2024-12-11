#pragma once

#include "Tokenizer.h"

namespace pcap_parser
{

const size_t TOKEN_IDENTITY_SIZE = 7;
enum TokenIdentity
{
    MagicNumber,
    Versions,
    Reserved1,
    Reserved2,
    SnapLen,
    LinkType,
    None
};

class FileHeaderToken : public BaseToken
{
public:
    FileHeaderToken() : BaseToken() {}
    FileHeaderToken(uint32_t tokenValue, TokenIdentity tokenIdentity) 
        : m_tokenValue(tokenValue), m_tokenIdentity(tokenIdentity)
    {}
    uint32_t m_tokenValue = 0;
    TokenIdentity m_tokenIdentity = TokenIdentity::None;
};

class FileHeaderTokenizer : public Tokenizer
{

public:
    FileHeaderTokenizer(std::string const& filepath);

    /*
    * Tokenizer methods
    */
    bool ReadToken(std::unique_ptr<BaseToken>& token) override;
    bool IsLastToken() const override;
    /**/
    TokenIdentity m_lastTokenIdentity = TokenIdentity::None;

    ~FileHeaderTokenizer();
};
    
} // namespace pcap_parser
