#include "PacketDataTokenizer.h"

namespace pcap_parser
{
    PacketDataTokenizer::PacketDataTokenizer(std::shared_ptr<std::ifstream> fileStream) : Tokenizer(fileStream)
    {}

    void PacketDataTokenizer::SetDataLength(size_t lengthInBytes)
    {
        m_length = lengthInBytes;
    }

    bool PacketDataTokenizer::ReadToken(std::unique_ptr<BaseToken> &token)
    {
        PacketDataToken dataToken;
        auto rc = m_reader.ReadBytes(m_length, dataToken.m_values);
        if (!rc)
        {
            return false;
        }
        token = std::make_unique<PacketDataToken>(dataToken);
        m_isTerminal = true;
        return true;
    }

    // 
    bool PacketDataTokenizer::IsLastToken() const
    {
        return m_isTerminal;
    }

    void PacketDataTokenizer::ResetTerminal()
    {
        m_isTerminal = false;
    }

    PacketDataTokenizer::~PacketDataTokenizer()
    {
    }

} // namespace pcap_parser
