#pragma once
#include <cstdlib>

namespace pcap_parser
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

} // namespace pcap_parser