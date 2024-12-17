#pragma once

#include "BaseToken.h"
#include "BaseTokenizer.h"
#include "Enums.h"
#include "Reader.h"

namespace pcap_parser
{
//TODO remove reader methods from tokenizer
class Tokenizer : BaseTokenizer
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

    virtual ~Tokenizer() {};
protected:
    /*
    * try read 4 bytes, read as much we have
    */
    enums::ValueStatus GetValue4Bytes(uint32_t &value)
    {
        std::vector<Byte> bytesToRead;
        if (!m_reader.ReadBytes(4, bytesToRead))
        {
            return enums::ValueStatus::NothingToRead;
        }
        if (bytesToRead.size() != 4)
        {
            return enums::ValueStatus::Tail;
        }
        for (auto byte : bytesToRead)
        {
            value <<= 8;
            value += byte;
        }
        return enums::ValueStatus::Ok;
    }

    Reader m_reader;
};
} // namespace pcap_parser