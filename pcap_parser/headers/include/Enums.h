#pragma once
#include <cstdlib>

namespace pcap_parser
{
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
} // namespace enums
} // namespace pcap_parser