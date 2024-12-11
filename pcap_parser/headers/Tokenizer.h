#pragma once
#include "Reader.h"
#include "BaseToken.h"

namespace pcap_parser
{

//TODO remove reader methods from tokenizer
class Tokenizer : public Reader
{

public:
    /*
    * Become a new owner of a stream 
    * @param filepath is a path to pcap file
    */
    Tokenizer(std::string const& filepath) : m_reader(filepath)
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

    virtual ~Tokenizer() {};
protected:
    Reader m_reader;
};

} // namespace pcap_parser