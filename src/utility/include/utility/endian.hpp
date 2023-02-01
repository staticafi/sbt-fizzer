#ifndef UTILITY_ENDIAN_HPP_INCLUDED
#   define UTILITY_ENDIAN_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>


inline bool is_this_little_endian_machine()
{
    return *reinterpret_cast<natural_32_bit const* const>("\1\0\0\0") == 1U;
}


#endif
