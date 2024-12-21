#pragma once
#include <cstdint>
#include <ctime>
#include <cmath>
#include <iomanip>
#include <sstream>

namespace utils
{
template <int8_t FixedExponent>
class Decimal 
{
public:
    Decimal() = default;
    Decimal(int64_t mantissa) : m_mantissa(mantissa) {}

    int64_t mantissa() const { return m_mantissa; }
    void setMantissa(int64_t mantissa) { m_mantissa = mantissa; }

    int8_t exponent() const { return FixedExponent; }

    double toDouble() const 
    {
        return static_cast<double>(m_mantissa) * std::pow(10, FixedExponent);
    }
    static int64_t getNullValue()
    {
        return 9223372036854775807;
    }

    friend std::ostream& operator<<(std::ostream& os, Decimal<FixedExponent> const& decimal) 
    {
        os << decimal.toDouble();
        return os;
    }

private:
    int64_t m_mantissa = 0;
    bool m_isNull;
};

inline std::string nanosecondsToRealTime(uint64_t nanoseconds) {
    time_t seconds = nanoseconds / 1'000'000'000;
    uint64_t remainingNanoseconds = nanoseconds % 1'000'000'000;

    std::tm* tm = std::gmtime(&seconds);
    std::ostringstream oss;
    oss << std::put_time(tm, "%Y-%m-%d %H:%M:%S") << "." << std::setw(9) << std::setfill('0') << remainingNanoseconds;

    return oss.str();
}   
inline std::string ipToDottedDecimal(uint32_t ip) {
    uint8_t b4 = (ip & 0xFF);
    uint8_t b3 = ((ip >> 8) & 0xFF);
    uint8_t b2 = ((ip >> 16) & 0xFF);
    uint8_t b1 = ((ip >> 24) & 0xFF);
    std::ostringstream oss;
    oss << (unsigned)b1 << "." << (unsigned)b2 << "." << (unsigned)b3 << "." << (unsigned)b4;
    return oss.str();
}

template <typename T>
inline T readLittleEndian(const uint8_t* data) {
    T value = 0;
    for (size_t i = 0; i < sizeof(T); i++) {
        value |= static_cast<T>(data[i]) << (i * 8);
    }
    return value;
}
} // namespace utils

