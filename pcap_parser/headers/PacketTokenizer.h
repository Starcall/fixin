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
    std::unique_ptr<BaseToken> PeekToken() const override;
    std::unique_ptr<BaseToken> RendToken() override;
    bool IsLastToken() const override;
    /**/
};
} // namespace pcap_parer