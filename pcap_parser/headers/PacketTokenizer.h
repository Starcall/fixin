#pragma once

#include "Tokenizer.h"

namespace pcap_parser
{
const size_t PACKET_TOKEN_IDENTITY_SIZE = 6;
enum PacketTokenIdentity
{
    Seconds,
    SideSeconds,
    CapturedLength,
    OriginalLength,
    Data,
    PacketNone
};
class PacketToken : public BaseToken
{
public:
    PacketToken() : BaseToken()
    {}
    PacketToken(uint32_t value, PacketTokenIdentity identity) : 
        BaseToken(value),
        m_tokenIdentity(identity)
    {}
    PacketTokenIdentity m_tokenIdentity = PacketTokenIdentity::PacketNone;
};

class PacketTokenizer : public Tokenizer
{
public:
    PacketTokenizer(std::shared_ptr<std::ifstream> fileStream);

    /*
    * Tokenizer methods
    */
    bool ReadToken(std::unique_ptr<BaseToken>& token) override;
    bool IsLastToken() const override;
    /**/

    PacketTokenIdentity m_lastTokenIdentity = PacketTokenIdentity::PacketNone;
    ~PacketTokenizer();
};
} // namespace pcap_parer