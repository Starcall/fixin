#include "Reader.h"
#include "../utils/Logger.hpp"
namespace pcap_parser
{

Reader::Reader(std::shared_ptr<std::ifstream> fileStream) : m_stream(fileStream)
{
}

bool Reader::PeekByte(Byte& byte) const
{
    if (!m_stream || !m_stream->is_open())
    {
        return false;
    }
    int value = m_stream->peek();
    if (value == std::char_traits<char>::eof())
    {
        return false;
    }
    byte = static_cast<Byte>(value);
    return true;
}

bool Reader::ReadByte(Byte& byte)
{
    auto rc = PeekByte(byte);

    if (!rc) 
    {
        return false;
    }
    m_stream->get(reinterpret_cast<char&>(byte));
    // since we can peek a byte it always can be read
    return true;
}

bool Reader::ReadBytes(size_t k, std::vector<Byte>& bytes)
{    
    if (!m_stream || !m_stream->is_open() || IsEOF())
    {
        return false;
    }
    // could be optimized by using old memory and old capcity
    bytes.resize(0);
    while (k--)
    {
        Byte byteToRead;
        auto rc = ReadByte(byteToRead);
        if (!rc)
        {
            break;
        }
        bytes.push_back(byteToRead);
    }
    return true;
}

bool Reader::IsEOF() const
{
    return m_stream->eof();
}

Reader::~Reader() {}
} // namespace pcap_parser