#pragma once
#include "include/Values.h"
#include "EthernetHeaderTokenizer.h"
#include "IPv4HeaderTokenizer.h"

namespace pcap_parser
{
namespace data_parser
{

std::ostream& operator<<(std::ostream& os, const EthernetHeaderValues& data);
std::ostream& operator<<(std::ostream& os, const IPv4HeaderValues& ipv4);
std::ostream& operator<<(std::ostream& os, const EthernetIPv4HeaderValues& eth_ipv4);

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
    // In case of this task I chose not to create ProtocolParser since we are parsing only EthernetProtocol
    bool ParseEthernetProtocolHeader(EthernetHeaderValues& parsedValues);
    bool ParseIPv4ProtocolHeader(IPv4HeaderValues& parsedValues);
    FileHeaderValues const& m_fileMetadata;
    PacketDataValues const& m_data;
    size_t m_firstUnprocessed = 0;
};


} // namespace data_parser
} // namespace pcap_parser
