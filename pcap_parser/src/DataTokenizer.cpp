#include "DataTokenizer.h"

namespace pcap_parser
{
    DataTokenizer::DataTokenizer(std::shared_ptr<std::ifstream> fileStream) : Tokenizer(fileStream)
    {}

    void DataTokenizer::SetDataLength(size_t lengthInBytes)
    {
        m_length = lengthInBytes;
    }

    bool DataTokenizer::ReadToken(std::unique_ptr<BaseToken> &token)
    {
        size_t bytesLeft = m_length;
        std::vector<BaseToken> baseTokens;
        std::vector<Byte> tail;
        while (bytesLeft >= 4)
        {
            uint32_t value = 0;
            if (GetValue4Bytes(value) != enums::ValueStatus::Ok)
            {
                return false;
            }
            bytesLeft -= 4;
            baseTokens.emplace_back(value);
        }
        if (bytesLeft)
        {
            auto rc = m_reader.ReadBytes(bytesLeft, tail);
            if (!rc)
            {
                // TODO insert log
                return false;
            }
        }
        // Could optimize, remove copying
        token = std::make_unique<DataToken>(DataToken(baseTokens, tail));
        m_isTerminal = true;
        return true;
    }

    // 
    bool DataTokenizer::IsLastToken() const
    {
        return m_isTerminal;
    }

    void DataTokenizer::ResetTerminal()
    {
        m_isTerminal = false;
    }

    DataTokenizer::~DataTokenizer()
    {
    }

} // namespace pcap_parser
