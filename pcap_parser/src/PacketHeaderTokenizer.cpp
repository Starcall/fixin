#include "PacketHeaderTokenizer.h"

/*
* probably I should have HeaderTokenizer class that implemented by FileHeaderTokenizer and PacketHeaderTokenizer
* and DataTokenizer that implemets Tokenizer
* if you see this text that means that I was to lazy to refactor it 
* it is unpaid anyway....
*/

namespace pcap_parser
{
    PacketHeaderTokenizer::PacketHeaderTokenizer(std::shared_ptr<std::ifstream> fileStream) : Tokenizer(fileStream)
    {}

    bool PacketHeaderTokenizer::ReadToken(std::unique_ptr<BaseToken> &token)
    {        
        uint32_t value = 0;
        if (GetValue4Bytes(value) != ValueStatus::Ok)
        {
            return false;
        }
        PacketTokenIdentity identity = static_cast<PacketTokenIdentity>((static_cast<int>(m_lastTokenIdentity) + 1) % PACKET_TOKEN_IDENTITY_SIZE);
        m_lastTokenIdentity = identity;
        token = std::make_unique<PacketHeaderToken>(PacketHeaderToken(value, identity));
        return true;
    }

    bool PacketHeaderTokenizer::IsLastToken() const
    {
        return m_lastTokenIdentity == PacketTokenIdentity::OriginalLength;
    }

    void PacketHeaderTokenizer::ResetTerminal()
    {
        m_lastTokenIdentity = PacketTokenIdentity::PacketNone;
    }

    PacketHeaderTokenizer::~PacketHeaderTokenizer()
    {
    }

} // namespace pcap_parser