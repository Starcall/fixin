#include "Reader.h"
#include "FileHeaderTokenizer.h"
#include "PacketHeaderTokenizer.h"
#include "DataTokenizer.h"
#include "ParserPCAP.h"

using namespace pcap_parser;


void GenerateHexText(std::string const& filepath, std::vector<Byte> const& values)
{
    std::ofstream file(filepath, std::ios::out | std::ios::binary);

    if (!file.is_open()) 
    {
        std::cerr << "Error: Unable to open the file: " << filepath << std::endl;
        return;
    }
    file.write(reinterpret_cast<const char*>(values.data()), values.size());


    file.close();
    std::cout << "Hexadecimal data written to: " << filepath << std::endl;
}

void BasicTesting()
{
// Reader Basic Test
    {
        GenerateHexText("./test/1024", {0x1, 0x0, 0x2, 0xF});
        auto reader_stream = std::make_shared<std::ifstream>(std::ifstream("./test/1024"));
        auto reader = Reader(reader_stream);
        std::vector<Byte> values;
        reader.ReadBytes(100, values);
        Logger logger = Logger();
        logger.log(Logger::LogLevel::Info, "main() ReaderTest " + std::to_string(values.size()));
        for (size_t i = 0; i < values.size(); i++)
        {
            logger.log(Logger::LogLevel::Info, "main() ReaderTest " + std::to_string(values[i]));
        }
    }
    // Tokenizer basic tests
    {

        auto tokenizerStream = std::make_shared<std::ifstream>(std::ifstream("./test/two_headers_and_some_data"));
        FileHeaderTokenizer tokenizer = FileHeaderTokenizer(tokenizerStream);
        Logger logger = Logger();
        while (!tokenizer.IsLastToken())
        {
            std::unique_ptr<BaseToken> token;
            auto rc = tokenizer.ReadToken(token); 
            logger.log(Logger::LogLevel::Info, "main() TokenizerTest rc =  " + std::to_string(rc));
            FileHeaderToken fileHeaderToken = *dynamic_cast<FileHeaderToken*>(token.get());
            logger.log(Logger::LogLevel::Info, "main() TokenizerTest identity =  " + 
                std::to_string(fileHeaderToken.m_tokenIdentity));
            logger.log(Logger::LogLevel::Info, "main() TokenizerTest value =  " + 
                std::to_string(fileHeaderToken.m_tokenValue));
        }
        int dataSize = 0;
        PacketHeaderTokenizer packetTokenizer = PacketHeaderTokenizer(tokenizerStream);
        while (!packetTokenizer.IsLastToken())
        {
            std::unique_ptr<BaseToken> token;
            auto rc = packetTokenizer.ReadToken(token); 
            if (!rc)
            {
                break;
            }
            logger.log(Logger::LogLevel::Info, "main() packetTokenizerTest rc =  " + std::to_string(rc));
            PacketHeaderToken packetToken = *dynamic_cast<PacketHeaderToken*>(token.get());
            logger.log(Logger::LogLevel::Info, "main() packetTokenizerTest identity =  " + 
                std::to_string(packetToken.m_tokenIdentity));
            logger.log(Logger::LogLevel::Info, "main() packetTokenizerTest value =  " + 
                std::to_string(packetToken.m_tokenValue));
            if (packetToken.m_tokenIdentity == PacketTokenIdentity::CapturedLength)
            {
                dataSize = __builtin_bswap32(packetToken.m_tokenValue);
                logger.log(Logger::LogLevel::Info, "data size is : " + std::to_string(dataSize));
            }
        }
        DataTokenizer dataTokenizer = DataTokenizer(tokenizerStream);
        dataTokenizer.SetDataLength(dataSize);
        std::unique_ptr<BaseToken> token;
        auto rc = dataTokenizer.ReadToken(token);
        logger.log(Logger::LogLevel::Info, "main() dataTokenizerTest rc =  " + std::to_string(rc));
        DataToken dataToken = *dynamic_cast<DataToken*>(token.get());
        for (auto value : dataToken.m_4BytesValues)
        {
            logger.log(Logger::LogLevel::Info, "main() dataTokenizerTest value = " + std::to_string(value.m_tokenValue));
        }
        for (auto value : dataToken.m_tail)
        {
            logger.log(Logger::LogLevel::Info, "main() dataTokenizerTest tail byte = " + std::to_string(value));
        }
        
    }
}

int main()
{
    ParserPCAP parser("./test/two_headers.pcap");
    FileHeaderValues values;
    auto rc = parser.ParseFileHeader(values);

    if (rc)
    {
        std::cout << values;
    }
    return 0;
}
