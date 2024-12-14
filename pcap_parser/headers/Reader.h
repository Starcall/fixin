#pragma once
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "../utils/Logger.hpp"

namespace pcap_parser
{
using Byte = unsigned char;

class Reader 
{
public:

    Reader() = default;
    /*
    * Constructor from a filestream. coping ownership of shared ptr to the stream 
    * @param filepath is a shared pointer to stream 
    */
    Reader(std::shared_ptr<std::ifstream> fileStream);

    Reader(Reader &&other) noexcept
    {
        m_stream = std::move(other.m_stream);
    };
    
    Reader& operator=(Reader&& other) noexcept
    {
        if (this != &other)
        {
            m_stream = std::move(other.m_stream);
        }
        return *this;
    }
    /*
    * Look at one byte from the input stream and stores it into a variable
    * @param byte - unsigned char to store
    * @return success status
    */
    bool PeekByte(Byte& byte) const;

    /*
    * Look at many bytes from the input stream
    * @param k a number of bytes to look at
    * @param bytes a vector to store bytes
    * @return success status
    */
    bool ReadByte(Byte& byte);

    /*
    * Read at many bytes from the input stream to the vector
    * @param k a number of bytes to look at
    * @param bytes vector to store bytes
    * @return success status
    */
    bool ReadBytes(size_t k, std::vector<Byte>& bytes);

    /*
    * Check if the stream reached end of file
    * @return bool if stream reached EOF
    */
    bool IsEOF() const;

    ~Reader();

private:
    std::shared_ptr<std::ifstream> m_stream;
};


} // namespace pcap_parser