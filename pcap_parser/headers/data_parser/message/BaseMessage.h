#pragma once

#include "include/Enums.h"
#include "include/Values.h"

namespace pcap_parser
{
namespace data_parser
{
namespace sbe_parser
{
class BaseMessage
{
public:
    BaseMessage() = default;
    BaseMessage(message::MessageHeaderValues const& header) : m_SBEHeader(header)
    {}

    virtual ~BaseMessage() {};
    message::MessageHeaderValues m_SBEHeader;
};
} // namespace sbe_parser
} // namespace data_parser
} // namespace pcap_parser
