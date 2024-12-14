#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <chrono>
#include <ctime>

namespace pcap_parser
{
class Logger 
{
public:
    enum class LogLevel 
    {
        Info,
        Warning,
        Error
    };

    Logger(const std::string& filename = "") 
    {
        if (!filename.empty()) 
        {
            logToFile = true;
            logFile.open(filename, std::ios::out | std::ios::app);
            if (!logFile.is_open()) 
            {
                std::cerr << "Error opening log file!" << std::endl;
            }
        }
    }

    ~Logger() 
    {
        if (logFile.is_open()) 
        {
            logFile.close();
        }
    }
    void log(LogLevel level, const std::string& message) 
    {
        std::string logMessage = getCurrentTime() + " [" + logLevelToString(level) + "] " + message;
        
        if (logToFile && logFile.is_open()) 
        {
            logFile << logMessage << std::endl;
        }

        std::cout << logMessage << std::endl; 
    }

private:
    std::string getCurrentTime() const
    {
        auto now = std::chrono::system_clock::now();
        auto now_time_t = std::chrono::system_clock::to_time_t(now);
        std::string time_str = std::ctime(&now_time_t);
        time_str.pop_back();
        return time_str;
    }

    std::string logLevelToString(LogLevel level) const
    {
        switch (level) {
            case LogLevel::Info: return "INFO";
            case LogLevel::Warning: return "WARNING";
            case LogLevel::Error: return "ERROR";
            default: return "UNKNOWN";
        }
    }

    bool logToFile = false;
    std::ofstream logFile;
};
} // namespace pcap_parser