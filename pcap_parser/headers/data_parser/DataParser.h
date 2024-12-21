#pragma once
#include "include/Values.h"
#include "EthernetHeaderTokenizer.h"
#include "IPv4HeaderTokenizer.h"
#include "UDPHeaderTokenizer.h"
#include "MarketDataHeaderTokenizer.h"
#include "IncrementalPacketHeaderTokenizer.h"

#include "message/MessageHeaderTokenizer.h"
#include "message/BaseMessage.h"
#include "message/OrderUpdateMessage.h"
#include "message/OrderExecuteMessage.h"

#include "../../utils/utils.hpp"

namespace pcap_parser
{
namespace data_parser
{

std::ostream& operator<<(std::ostream& os, const EthernetHeaderValues& data);
std::ostream& operator<<(std::ostream& os, const IPv4HeaderValues& ipv4);
std::ostream& operator<<(std::ostream& os, const EthernetIPv4HeaderValues& eth_ipv4);
std::ostream& operator<<(std::ostream& os, const UPDHeaderValues& udp);
std::ostream& operator<<(std::ostream& os, const EthernetIPv4UDPHeaderValues& eth_ipv4_udp);
std::ostream& operator<<(std::ostream& os, const MarketDataHeaderValues& md);
std::ostream& operator<<(std::ostream& os, const MarketDataUDPHeaderValues& md);
std::ostream& operator<<(std::ostream& os, const IncrementalPacketHeaderValues& values);
std::ostream& operator<<(std::ostream& os, const InrementalPacketMDUDPValues& values);
std::ostream& operator<<(std::ostream& os, const message::MessageHeaderValues& header);
class DataParser
{
public:
    DataParser(FileHeaderValues const& fileMetadata, PacketDataValues const& dataToParse)
        : m_fileMetadata(fileMetadata),
          m_data(dataToParse)
    {}

    /*
    * @param parsedValues pointer to struct that will hold parsed values
    */
    bool ParseProtocolHeadersData(std::unique_ptr<BasicProtocolValues> &parsedValues);

    /*
    * @param parsedValues struct with message header values
    */
    bool ParseMessageHeaderData(message::MessageHeaderValues& parsedValues);

    bool ParseMessageData(std::unique_ptr<sbe_parser::BaseMessage>& parsedMessage, enums::message::MessageType type);

private:
    // In case of this task I chose not to create ProtocolParser for simplification since we are parsing only EthernetProtocol
    bool ParseEthernetProtocolHeader(EthernetHeaderValues& parsedValues);
    bool ParseIPv4ProtocolHeader(IPv4HeaderValues& parsedValues);
    bool ParseUDPHeader(UPDHeaderValues& parsedValues);
    bool ParseMarketDataHeader(MarketDataHeaderValues& parsedValues);
    bool ParseIncrementalPacketHeader(IncrementalPacketHeaderValues& parsedValues);


    FileHeaderValues const& m_fileMetadata;
    PacketDataValues const& m_data;
    size_t m_firstUnprocessed = 0;
};


} // namespace data_parser
} // namespace pcap_parser
