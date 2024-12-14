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
            if (GetValue4Bytes(value) != ValueStatus::Ok)
            {
                // TODO insert log
                return false;
            }
            bytesLeft -= 4;
            baseTokens.emplace_back(value);
        }
        if (bytesLeft)
        {
            auto rc = ReadBytes(bytesLeft, tail);
            if (!rc)
            {
                // TODO insert log
                return false;
            }
        }
        // Could optimize, remove copying
        token = std::make_unique<DataToken>(DataToken(baseTokens, tail));
        return true;
    }

    bool DataTokenizer::IsLastToken() const
    {
        return true;
    }

    DataTokenizer::~DataTokenizer()
    {
    }

} // namespace pcap_parser
