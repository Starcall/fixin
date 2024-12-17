#pragma once

#include "include/Enums.h"
#include "include/Tokenizer.h"

namespace pcap_parser
{

class PacketHeaderToken : public BaseToken
{
public:
    PacketHeaderToken() : BaseToken()
    {}
    PacketHeaderToken(uint32_t value, enums::PacketTokenIdentity identity) : 
        BaseToken(value),
        m_tokenIdentity(identity)
    {}
    enums::PacketTokenIdentity m_tokenIdentity = enums::PacketTokenIdentity::PacketNone;
};

class PacketHeaderTokenizer : public Tokenizer
{
public:
    PacketHeaderTokenizer() : Tokenizer()
    {
        m_lastTokenIdentity = enums::PacketTokenIdentity::PacketNone;
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
    * BaseTokenizer methods
    */
    bool ReadToken(std::unique_ptr<BaseToken>& token) override;
    bool IsLastToken() const override;
    void ResetTerminal() override;
    /**/
    
    ~PacketHeaderTokenizer();
private:
    enums::PacketTokenIdentity m_lastTokenIdentity = enums::PacketTokenIdentity::PacketNone;
    
};
} // namespace pcap_parer