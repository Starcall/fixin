#pragma once

#include "memory"

#include "BaseToken.h"

namespace pcap_parser
{
class BaseTokenizer
{
public:
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

    virtual ~BaseTokenizer() {}
};
    
} // namespace pcap_parser
