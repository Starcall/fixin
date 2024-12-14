#pragma once

#include "Tokenizer.h"

namespace pcap_parser
{
const size_t PACKET_TOKEN_IDENTITY_SIZE = 5;
enum PacketTokenIdentity
{
    Seconds,
    SideSeconds,
    CapturedLength,
    OriginalLength,
    PacketNone
};
class PacketHeaderToken : public BaseToken
{
public:
    PacketHeaderToken() : BaseToken()
    {}
    PacketHeaderToken(uint32_t value, PacketTokenIdentity identity) : 
        BaseToken(value),
        m_tokenIdentity(identity)
    {}
    PacketTokenIdentity m_tokenIdentity = PacketTokenIdentity::PacketNone;
};

class PacketHeaderTokenizer : public Tokenizer
{
public:
    PacketHeaderTokenizer() : Tokenizer()
    {
        m_lastTokenIdentity = PacketTokenIdentity::PacketNone;
    }
    PacketHeaderTokenizer(std::shared_ptr<std::ifstream> fileStream);
    PacketHeaderTokenizer(PacketHeaderTokenizer&& other) noexcept : Tokenizer(std::move(other))
    {
        m_lastTokenIdentity = other.m_lastTokenIdentity;
    }
    PacketHeaderTokenizer& operator=(PacketHeaderTokenizer&& other) noexcept
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
    ~PacketHeaderTokenizer();
private:
    PacketTokenIdentity m_lastTokenIdentity = PacketTokenIdentity::PacketNone;
    
};
} // namespace pcap_parer