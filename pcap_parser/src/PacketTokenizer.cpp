#include "PacketTokenizer.h"

namespace pcap_parser
{
    PacketTokenizer::PacketTokenizer(std::shared_ptr<std::ifstream> fileStream) : Tokenizer(fileStream)
    {}

    bool PacketTokenizer::ReadToken(std::unique_ptr<BaseToken> &token)
    {        
        uint32_t value = 0;
        auto rc = GetValue(value);
        if (rc == ValueStatus::NothingToRead)
        {
            return false;
        }
        PacketTokenIdentity identity;
        if (m_lastTokenIdentity != PacketTokenIdentity::Data)
        {
            if (rc != ValueStatus::Ok)
            {
                // add info
                return false;
            }
            // all other tokens are data
            identity = static_cast<PacketTokenIdentity>((static_cast<int>(m_lastTokenIdentity) + 1) % PACKET_TOKEN_IDENTITY_SIZE);
            m_lastTokenIdentity = identity;
        }
        else
        {
            identity = m_lastTokenIdentity;
        }
        token = std::make_unique<PacketToken>(PacketToken(value, identity));
        return true;
    }

    bool PacketTokenizer::IsLastToken() const
    {
        return m_reader.IsEOF();
    }

    PacketTokenizer::~PacketTokenizer()
    {
    }

} // namespace pcap_parser