#pragma once
#include "Reader.h"
#include "BaseToken.h"

namespace pcap_parser
{

class Tokenizer : public Reader
{

public:
    /*
    * Become a new owner of a stream 
    * @param filepath is a path to pcap file
    */
    Tokenizer(std::string const& filepath);

    /*
    * Look at one token from the input stream
    * @return unique pointer to a BaseToken class
    */
    virtual std::unique_ptr<BaseToken> PeekToken() const;

    /*
    * Read at one token from the input stream
    * @return unique pointer to a BaseToken class
    */
    virtual std::unique_ptr<BaseToken> RendToken();

    /*
    * Check if the tokenizer reached its last token
    */
    virtual bool IsLastToken() const;

    virtual ~Tokenizer();
private:
    Reader m_reader;
};

} // namespace pcap_parser