#pragma once
#include "cstdlib"
#include <vector>

#include "Enums.h"
#include "link_tokenizers/LinkTypeTokenizer.h"
#include "Values.h"


namespace pcap_parser
{
namespace data_parser
{
using Byte = unsigned char;
class DataParser
{
public:
    DataParser() = default;
    DataParser(FileHeaderValues const& fileMetadata, PacketHeaderValues const& packetMetadata) 
        : m_fileMetadata(fileMetadata), m_packetMetadata(packetMetadata)
    {}
private:
    FileHeaderValues m_fileMetadata;
    PacketHeaderValues m_packetMetadata;

    std::unique_ptr<LinkTypeTokenizer> m_tokenizer;
};

} // namespace data_parser
} // namespace data_parser
