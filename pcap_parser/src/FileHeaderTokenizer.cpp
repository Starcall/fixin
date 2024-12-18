
#include "FileHeaderTokenizer.h"

namespace pcap_parser
{

    FileHeaderTokenizer::FileHeaderTokenizer(std::shared_ptr<std::ifstream> fileStream) : Tokenizer(fileStream)
    {}

    bool FileHeaderTokenizer::ReadToken(std::unique_ptr<BaseToken>& token)
    {
        uint32_t value = 0;
        if (GetValue4Bytes(value) != enums::ValueStatus::Ok)
        {
            return false;
        }
        enums::HeaderTokenIdentity identity;
        identity = static_cast<enums::HeaderTokenIdentity>((static_cast<int>(m_lastTokenIdentity) + 1) % enums::HEADER_TOKEN_IDENTITY_SIZE);
        m_lastTokenIdentity = identity;
        token = std::make_unique<FileHeaderToken>(FileHeaderToken(value, identity));
        return true;
    }

    bool FileHeaderTokenizer::IsLastToken() const
    {
        return m_lastTokenIdentity == enums::HeaderTokenIdentity::LinkType;
    }

    void FileHeaderTokenizer::ResetTerminal()
    {
        m_lastTokenIdentity = enums::HeaderTokenIdentity::HeaderNone;
    }

    FileHeaderTokenizer::~FileHeaderTokenizer() 
    {
    }

} // namespace pcap_parser