#pragma once

#include "FileHeaderTokenizer.h"

namespace pcap_parser
{

    FileHeaderTokenizer::FileHeaderTokenizer(std::string const &filepath) : Tokenizer(filepath)
    {}

    bool FileHeaderTokenizer::ReadToken(std::unique_ptr<BaseToken>& token)
    {
        std::vector<Byte> bytesToRead;
        if (!m_reader.ReadBytes(4, bytesToRead))
        {
            return false;
        }
        if (bytesToRead.size() != 4)
        {
            return false;
        }
        uint32_t value = 0;
        TokenIdentity identity;
        for (auto byte : bytesToRead)
        {
            value *= 256;
            value += byte;
        }
        identity = static_cast<TokenIdentity>((static_cast<int>(m_lastTokenIdentity) + 1) % TOKEN_IDENTITY_SIZE);
        m_lastTokenIdentity = identity;
        token = std::make_unique<FileHeaderToken>(FileHeaderToken(value, identity));
        return true;
    }

    bool FileHeaderTokenizer::IsLastToken() const
    {
        return m_lastTokenIdentity == TokenIdentity::LinkType;
    }

    FileHeaderTokenizer::~FileHeaderTokenizer() 
    {
    }

} // namespace pcap_parser