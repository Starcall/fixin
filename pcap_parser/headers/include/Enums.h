#pragma once
#include <cstdlib>

namespace pcap_parser
{

using Byte = unsigned char;

namespace enums
{
const size_t HEADER_TOKEN_IDENTITY_SIZE = 7;
enum HeaderTokenIdentity
{
    MagicNumber,
    Versions,
    Reserved1,
    Reserved2,
    SnapLen,
    LinkType,
    HeaderNone
};

const size_t PACKET_TOKEN_IDENTITY_SIZE = 5;
enum PacketTokenIdentity
{
    Seconds,
    SideSeconds,
    CapturedLength,
    OriginalLength,
    PacketNone
};

const size_t ETHERNET_HEADER_TOKEN_IDENTITY_SIZE = 4;
enum EthernetHeaderTokenIdentity
{
    DestinationMac,
    SourceMac,
    Type,
    EthernetNone
};

const size_t IPV4_HEADER_TOKEN_IDENTITY_SIZE = 14;
enum IPv4HeaderTokenIdentity
{
    Version,
    IHL,
    TypeOfService,
    TotalLength,
    Identification,
    Flags,
    FragmentOffset,
    TTL,
    Protocol,
    Checksum,
    SourceIP,
    DestinationIp,
    Options,
    IPv4None
};

const size_t UPD_HEADER_TOKEN_IDENTITY_SIZE = 5;
enum UPDHeaderTokenIdentity
{
    SourcePort,
    DestinationPort,
    Length,
    ChecksumUDP,
    UDPNone
};

const size_t MARKET_DATA_TOKEN_IDENTITY_SIZE = 5;
enum MarketDataTokenIdentity
{
    MsgSeqNum,
    MsgSize,
    MsgFlags,
    SendingTime,
    MarketDataNone
};

const size_t INCREMENTAL_PACKET_HEADER_TOKEN_IDENTITY_SIZE = 3;
enum IncrementalPacketHeaderTokenIdentity {
    TransactTime,
    ExchangeTradingSessionID,
    IncrementalPacketNone
};



enum Endian
{
    BigEndian,
    LittleEndian,
    None
};

enum ValueStatus
{
    Ok,
    NothingToRead,
    Tail
};

enum PacketType
{
    Incremental,
    Snapshot,
    Unrecognized
};

namespace message
{

const size_t MESSAGE_HEADER_TOKEN_SIZE = 5;
enum MessageHeaderTokenIdenity
{
    BlockLength,
    TemplateID,
    SchemaID,
    Version,
    MessageHeaderNone
};

enum MessageType
{
    OrderUpdate,
    OrderExecution,
    OrderBookSnapshot,
    Unsupported
};
} // namespace message



} // namespace enums
} // namespace pcap_parser