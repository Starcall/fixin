#pragma once
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace pcap_parser
{

using Byte = unsigned char;

class Reader 
{
public:
    /*
    * Constructor from a filepath. Creates shared ptr to stream 
    * @param filepath is a path to create stream with
    */
    Reader(std::string const& filePath);

    
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
    bool PeekBytes(size_t k, std::vector<Byte>& bytes) const;

    /*
    * Read one byte from the input stream to a variable
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
    bool m_EOFReached = false;
};



} // namespace pcap_parser