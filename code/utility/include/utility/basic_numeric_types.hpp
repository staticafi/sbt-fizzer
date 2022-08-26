#ifndef UTILITY_BASIC_NUMERIC_TYPES_HPP_INCLUDED
#   define UTILITY_BASIC_NUMERIC_TYPES_HPP_INCLUDED

#   include <utility/typefn_if_then_else.hpp>
#   include <cstdint>
#   include <limits>


typedef int8_t   integer_8_bit;
typedef int16_t  integer_16_bit;
typedef int32_t  integer_32_bit;
typedef int64_t  integer_64_bit;

typedef uint8_t   natural_8_bit;
typedef uint16_t  natural_16_bit;
typedef uint32_t  natural_32_bit;
typedef uint64_t  natural_64_bit;

typedef typefn_if_then_else<
                std::numeric_limits<float>::is_iec559 &&
                std::numeric_limits<float>::radix == 2 &&
                std::numeric_limits<float>::digits == 24 &&
                std::numeric_limits<float>::digits10 == 6 &&
                std::numeric_limits<float>::max_digits10 == 9 &&
                sizeof(float)*8U == 32U,
                float,
                void>::result
        float_32_bit;

typedef typefn_if_then_else<
                std::numeric_limits<double>::is_iec559 &&
                std::numeric_limits<double>::radix == 2 &&
                std::numeric_limits<double>::digits == 53 &&
                std::numeric_limits<double>::digits10 == 15 &&
                std::numeric_limits<double>::max_digits10 == 17 &&
                sizeof(double)*8U == 64U,
                double,
                void>::result
        float_64_bit;


#endif
