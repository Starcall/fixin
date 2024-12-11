#pragma once

namespace pcap_parser
{

class BaseToken
{
public:
    BaseToken() = default;
    BaseToken(uint32_t tokenValue) : m_tokenValue(tokenValue) {}
    virtual ~BaseToken() = default;
    uint32_t m_tokenValue = 0;
};
} // namespace pcap_parser