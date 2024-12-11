#pragma once

#include "Tokenizer.h"

namespace pcap_parser
{
class PacketTokenizer : BaseToken
{

};

class PacketTokenizer : public Tokenizer
{
public:
    PacketTokenizer(std::string const& filepath);

    /*
    * Tokenizer methods
    */
    std::unique_ptr<BaseToken> ReadToken() override;
    bool IsLastToken() const override;
    /**/
};
} // namespace pcap_parer