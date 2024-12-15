#pragma once

#include "BaseToken.h"
#include "Enums.h"
#include "Reader.h"

namespace pcap_parser
{
//TODO remove reader methods from tokenizer
class Tokenizer
{

public:

    Tokenizer() = default;
    /*
    * Become a new owner of a stream 
    * @param filepath is a path to pcap file
    */
    Tokenizer(std::shared_ptr<std::ifstream> fileStream) : m_reader(fileStream)
    {}

    Tokenizer(Tokenizer&& other) noexcept
    {
        m_reader = std::move(other.m_reader);
    }
    Tokenizer& operator=(Tokenizer&& other) noexcept
    {
        if (this != &other)
        {
            m_reader = std::move(other.m_reader);
        }
        return *this;
    }
    /*
    * Read at one token from the input stream and store it in pointer
    * @return read success
    */
    virtual bool ReadToken(std::unique_ptr<BaseToken>&) = 0;

    /*
    * Check if the tokenizer reached its last token
    */
    virtual bool IsLastToken() const = 0;

    /*
    * Reset state before parsing new token
    * IsLastToken -> false
    */
    virtual void ResetTerminal() = 0;

    virtual ~Tokenizer() {};
protected:
    /*
    * try read 4 bytes, read as much we have
    */
    ValueStatus GetValue4Bytes(uint32_t &value)
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

    Reader m_reader;
};
} // namespace pcap_parser