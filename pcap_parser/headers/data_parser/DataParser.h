#pragma once
#include "include/Values.h"
#include "EthernetHeaderTokenizer.h"

namespace pcap_parser
{
namespace data_parser
{

std::ostream& operator<<(std::ostream& os, const EthernetDataValues& data);

class DataParser
{
public:
    DataParser(FileHeaderValues const& fileMetadata, PacketDataValues const& dataToParse)
        : m_fileMetadata(fileMetadata),
          m_data(dataToParse)
    {}

    /*
    * @param pointer to struct that will hold parsed values
    */
    bool ParseData(std::unique_ptr<BasicProtocolValues> &parsedValues);

private:
    bool ParseEthernetProtocol(EthernetDataValues& parsedValues);
    FileHeaderValues const& m_fileMetadata;
    PacketDataValues const& m_data;
};


} // namespace data_parser
} // namespace pcap_parser
