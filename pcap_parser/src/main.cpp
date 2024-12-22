#include "Reader.h"
#include "FileHeaderTokenizer.h"
#include "PacketHeaderTokenizer.h"
#include "PacketDataTokenizer.h"
#include "ParserPCAP.h"
#include "data_parser/DataParser.h"
#include "include/Values.h"

using namespace pcap_parser;
using namespace pcap_parser::data_parser;


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
            if (packetToken.m_tokenIdentity == enums::CapturedLength)
            {
                dataSize = __builtin_bswap32(packetToken.m_tokenValue);
                logger.log(Logger::LogLevel::Info, "data size is : " + std::to_string(dataSize));
            }
        }
        PacketDataTokenizer dataTokenizer = PacketDataTokenizer(tokenizerStream);
        dataTokenizer.SetDataLength(dataSize);
        std::unique_ptr<BaseToken> token;
        auto rc = dataTokenizer.ReadToken(token);
        logger.log(Logger::LogLevel::Info, "main() dataTokenizerTest rc =  " + std::to_string(rc));
        PacketDataToken dataToken = *dynamic_cast<PacketDataToken*>(token.get());
        for (auto value : dataToken.m_values)
        {
            logger.log(Logger::LogLevel::Info, "main() dataTokenizerTest value = " + std::to_string(value));
        }
        
    }
}

int main()
{
    //ParserPCAP parser("./ignore/2023-10-09.1849-1906.pcap");
    ParserPCAP parser("./ignore/2023-10-10.0845-0905.pcap");
    FileHeaderValues fileHeaderValues;
    auto rc = parser.ParseFileHeader(fileHeaderValues);

    if (rc)
    {
        std::cout << fileHeaderValues;
    }
    PacketHeaderValues packetHeaderValues;
    while (parser.ParsePacketHeader(packetHeaderValues, fileHeaderValues))
    {
        PacketDataValues packetDataValues;
        auto s = parser.ParsePacketData(packetDataValues, packetHeaderValues, fileHeaderValues);
        //std::cout << packetDataValues;
        data_parser::DataParser dataParser = data_parser::DataParser(fileHeaderValues, packetDataValues);
        std::unique_ptr<BasicProtocolValues> parsedProtocolData;
        auto rc = dataParser.ParseProtocolHeadersData(parsedProtocolData);
        //std::cout << rc << "\n";
        //std::unique_ptr<InrementalPacketMDUDPValues> MDValues = std::unique_ptr<InrementalPacketMDUDPValues>(dynamic_cast<InrementalPacketMDUDPValues*>(parsedProtocolData.release()));
        std::unique_ptr<MarketDataUDPHeaderValues> MDValues = std::unique_ptr<MarketDataUDPHeaderValues>(dynamic_cast<MarketDataUDPHeaderValues*>(parsedProtocolData.release()));
        if (MDValues)
        {
            // snapshot
            std::cout << *MDValues.get();
        
            message::MessageHeaderValues parsedMessageHeader;
            rc = dataParser.ParseMessageHeaderData(parsedMessageHeader);
            if (parsedMessageHeader.TemplateID == 17)
            {

                std::cout << parsedMessageHeader;
                std::unique_ptr<sbe_parser::BaseMessage> parsedMessageData = std::make_unique<sbe_parser::BaseMessage>(parsedMessageHeader);
                rc = dataParser.ParseMessageData(parsedMessageData, enums::message::MessageType::OrderBookSnapshot);
                std::cout  << rc << "\n";
                std::unique_ptr<sbe_parser::OrderBookSnapshot> orderExecuteMessage = std::unique_ptr<sbe_parser::OrderBookSnapshot>(dynamic_cast<sbe_parser::OrderBookSnapshot*>(parsedMessageData.release()));
                std::cout << *orderExecuteMessage.get();
                break;

            }
            parser.ResetTokenizersTerminals();
            continue;
        }
        else
        {
            parser.ResetTokenizersTerminals();
            continue;
        }
        //std::cout << *MDValues.get();
        
        message::MessageHeaderValues parsedMessageHeader;
        rc = dataParser.ParseMessageHeaderData(parsedMessageHeader);
        //std::cout << rc << "\n";
        /*if (parsedMessageHeader.TemplateID == 15) {
            //std::cout << *MDValues.get();

            std::cout << parsedMessageHeader;
            std::unique_ptr<sbe_parser::BaseMessage> parsedMessageData = std::make_unique<sbe_parser::BaseMessage>(parsedMessageHeader);
            rc = dataParser.ParseMessageData(parsedMessageData, enums::message::MessageType::OrderUpdate);
            std::cout  << rc << "\n";
            std::unique_ptr<sbe_parser::OrderUpdateMessage> orderUpdateMessage = std::unique_ptr<sbe_parser::OrderUpdateMessage>(dynamic_cast<sbe_parser::OrderUpdateMessage*>(parsedMessageData.release()));
            std::cout << *orderUpdateMessage.get();
        }
        if (parsedMessageHeader.TemplateID == 16) {
            //std::cout << *MDValues.get();

            std::cout << parsedMessageHeader;
            std::unique_ptr<sbe_parser::BaseMessage> parsedMessageData = std::make_unique<sbe_parser::BaseMessage>(parsedMessageHeader);
            rc = dataParser.ParseMessageData(parsedMessageData, enums::message::MessageType::OrderExecution);
            std::cout  << rc << "\n";
            std::unique_ptr<sbe_parser::OrderExecutionMessage> orderExecuteMessage = std::unique_ptr<sbe_parser::OrderExecutionMessage>(dynamic_cast<sbe_parser::OrderExecutionMessage*>(parsedMessageData.release()));
            std::cout << *orderExecuteMessage.get();
        } */
        if (parsedMessageHeader.TemplateID == 17)
        {

            std::cout << parsedMessageHeader;
            std::unique_ptr<sbe_parser::BaseMessage> parsedMessageData = std::make_unique<sbe_parser::BaseMessage>(parsedMessageHeader);
            rc = dataParser.ParseMessageData(parsedMessageData, enums::message::MessageType::OrderBookSnapshot);
            std::cout  << rc << "\n";
            std::unique_ptr<sbe_parser::OrderBookSnapshot> orderExecuteMessage = std::unique_ptr<sbe_parser::OrderBookSnapshot>(dynamic_cast<sbe_parser::OrderBookSnapshot*>(parsedMessageData.release()));
            std::cout << *orderExecuteMessage.get();
            break;
        }
        parser.ResetTokenizersTerminals();
        
    }
    return 0;
}
