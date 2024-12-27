#include "Reader.h"
#include "FileHeaderTokenizer.h"
#include "PacketHeaderTokenizer.h"
#include "PacketDataTokenizer.h"
#include "ParserPCAP.h"
#include "data_parser/DataParser.h"
#include "include/Values.h"
#include "include/json.hpp"

using namespace pcap_parser;
using namespace pcap_parser::data_parser;


using json = nlohmann::json;

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

json SerializePacketHeaders(std::unique_ptr<BasicProtocolValues> const& parsedProtocolData, enums::PacketType type)
{
    json packet;
    switch (type)
    {
        case enums::PacketType::Unrecognized:
        {
            assert(false);
            break;
        }
        case enums::PacketType::Incremental:
        {

            auto incrementalMDValues = dynamic_cast<InrementalPacketMDUDPValues*>(parsedProtocolData.get());
            if (incrementalMDValues)
            {
                InrementalPacketMDUDPValues::to_json(packet, *incrementalMDValues);
            }
            break;
        }
        case enums::PacketType::Snapshot:
        {
            auto MDValues = dynamic_cast<MarketDataUDPHeaderValues*>(parsedProtocolData.get());
            if (MDValues)
            {
                MarketDataUDPHeaderValues::to_json(packet, *MDValues);
            }
            break;
        }
    }
    return packet;
} 
json SerializePacket(std::unique_ptr<BasicProtocolValues> const& parsedProtocolData, enums::PacketType type, std::vector<std::unique_ptr<sbe_parser::BaseMessage>> const& messages, std::vector<enums::message::MessageType> const& messageTypes)
{
    json serializedJson = SerializePacketHeaders(parsedProtocolData, type);
    assert(messages.size() == messageTypes.size());

    json serializedMessages = json::array();
    for (size_t i = 0; i < messages.size(); i++)
    {
        auto messageType = messageTypes[i];
        auto const& message = messages[i];
        switch(messageType)
        {
            case enums::message::MessageType::Unsupported:
            {
                serializedMessages.push_back("Unsupported message");
                break;
            }
            case enums::message::MessageType::OrderUpdate:
            {
                auto orderUpdateMessage = dynamic_cast<const sbe_parser::OrderUpdateMessage*>(message.get());
                assert(orderUpdateMessage);
                serializedMessages.push_back(*orderUpdateMessage);
                break;
            }
            case enums::message::MessageType::OrderExecution:
            {
                auto orderExecutionMessage = dynamic_cast<const sbe_parser::OrderExecutionMessage*>(message.get());
                assert(orderExecutionMessage);
                serializedMessages.push_back(*orderExecutionMessage);
                break;
            }
            case enums::message::MessageType::OrderBookSnapshot:
            {
                auto orderBookSnapshotMessage = dynamic_cast<const sbe_parser::OrderBookSnapshot*>(message.get());
                assert(orderBookSnapshotMessage);
                serializedMessages.push_back(*orderBookSnapshotMessage);
                break;
            }
        }
    }
    serializedJson["Messages"] = serializedMessages;
    return serializedJson;
}

void print_usage()
{
    std::cout << "./parser_pcap <input_file.pcap> <output_file>";
};

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        print_usage();
        return 0;
    }

    ParserPCAP parser(argv[1]);
    std::ofstream outFile(argv[2]);
    // diagnostic
    auto start = std::chrono::high_resolution_clock::now();
    size_t packetNums = 0;
    size_t failedMessages = 0;

    FileHeaderValues fileHeaderValues;
    auto rc = parser.ParseFileHeader(fileHeaderValues);
    if (rc)
    {
        std::cout << fileHeaderValues;
    }
    PacketHeaderValues packetHeaderValues;
    while (parser.ParsePacketHeader(packetHeaderValues, fileHeaderValues))
    {
        packetNums++;
        PacketDataValues packetDataValues;
        auto s = parser.ParsePacketData(packetDataValues, packetHeaderValues, fileHeaderValues);
        data_parser::DataParser dataParser = data_parser::DataParser(fileHeaderValues, packetDataValues);
        std::unique_ptr<BasicProtocolValues> parsedProtocolData;
        auto type = dataParser.ParseProtocolHeadersData(parsedProtocolData);


        std::vector<std::unique_ptr<sbe_parser::BaseMessage>> messages;
        std::vector<enums::message::MessageType> messageTypes;
        auto getMessageType = [](int msgNum) -> enums::message::MessageType {
            switch(msgNum)
            {
                case 15:
                {
                    return enums::message::MessageType::OrderUpdate;
                }
                case 16:
                {
                    return enums::message::MessageType::OrderExecution;
                }
                case 17:
                {
                    return enums::message::MessageType::OrderBookSnapshot;
                }
                default:
                {
                    return enums::message::MessageType::Unsupported;
                }
            }
        };

        if (type == enums::PacketType::Incremental)
        {
            message::MessageHeaderValues parsedMessageHeader;
            while(dataParser.ParseMessageHeaderData(parsedMessageHeader))
            {
                std::unique_ptr<sbe_parser::BaseMessage> parsedMessageData = std::make_unique<sbe_parser::BaseMessage>(parsedMessageHeader);
                rc = dataParser.ParseMessageData(parsedMessageData, getMessageType(parsedMessageHeader.TemplateID));
                if (!rc && getMessageType(parsedMessageHeader.TemplateID) != enums::message::MessageType::Unsupported)
                {
                    failedMessages++;
                    std::cout << "Failed to parse known message. " << " skipping it.\n";
                    continue;
                }
                messageTypes.push_back(getMessageType(parsedMessageHeader.TemplateID));
                messages.push_back(std::move(parsedMessageData));
            }
        }
        if (type == enums::PacketType::Snapshot)
        {
            message::MessageHeaderValues parsedMessageHeader;
            rc = dataParser.ParseMessageHeaderData(parsedMessageHeader);
            if (!rc)
            {
                std::cout << "Failed to parse message header";
            }
            std::unique_ptr<sbe_parser::BaseMessage> parsedMessageData = std::make_unique<sbe_parser::BaseMessage>(parsedMessageHeader);
            rc = dataParser.ParseMessageData(parsedMessageData, getMessageType(parsedMessageHeader.TemplateID));
            messageTypes.push_back(getMessageType(parsedMessageHeader.TemplateID));
            messages.push_back(std::move(parsedMessageData));  
        }
        auto json = SerializePacket(parsedProtocolData, type, messages, messageTypes);
        
        outFile << json.dump(2) << std::endl;
        parser.ResetTokenizersTerminals();
    }
    auto elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start).count();
    std::cout << "Elapsed: " << elapsedTime << " ms.\n" << "Number of packets parsed: " << packetNums << std::endl << "Average time on packet: " << elapsedTime * 1.0 / packetNums << " ms.\n Failed to parse " << failedMessages << " messages.";
    return 0;
}
