#pragma once

#include <memory>

#include "../ether_protocol_tokenizers/EtherProtocolTokenizer.h"
#include "LinkTypeTokenizer.h"

namespace pcap_parser
{
namespace data_parser
{

class TokenizerType1 : public LinkTypeTokenizer
{

    std::unique_ptr<EtherProtocolTokenizer> m_etherTokenizer;
};
    
} // namespace data_parser
} // namespace pcap_parser
