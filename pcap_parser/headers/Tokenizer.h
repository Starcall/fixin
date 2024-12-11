#pragma once
#include "Reader.h"
#include "BaseToken.h"

namespace pcap_parser
{
//TODO remove reader methods from tokenizer
class Tokenizer : public Reader
{

public:
    enum ValueStatus
    {
        Ok,
        NothingToRead,
        Tail
    };
    /*
    * Become a new owner of a stream 
    * @param filepath is a path to pcap file
    */
    Tokenizer(std::shared_ptr<std::ifstream> fileStream) : m_reader(fileStream)
    {}
    /*
    * Read at one token from the input stream and store it in pointer
    * @return read success
    */
    virtual bool ReadToken(std::unique_ptr<BaseToken>&) = 0;

    /*
    * Check if the tokenizer reached its last token
    */
    virtual bool IsLastToken() const = 0;


    ValueStatus GetValue(uint32_t &value)
    {
        std::vector<Byte> bytesToRead;
        if (!m_reader.ReadBytes(4, bytesToRead))
        {
            return ValueStatus::NothingToRead;
        }
        if (bytesToRead.size() != 4)
        {
            return ValueStatus::Tail;
        }
        for (auto byte : bytesToRead)
        {
            value *= 256;
            value += byte;
        }
        return ValueStatus::Ok;
    }

    virtual ~Tokenizer() {};
protected:
    Reader m_reader;
};
} // namespace pcap_parser