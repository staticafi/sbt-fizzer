#ifndef UTILITY_BIT_COUNT_HPP_INCLUDED
#   define UTILITY_BIT_COUNT_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>
#   include <utility/typefn_if_then_else.hpp>
#   include <utility/assumptions.hpp>


natural_8_bit  compute_num_of_bits_to_store_number(natural_32_bit  number);
natural_8_bit  compute_byte_aligned_num_of_bits_to_store_number(natural_32_bit  number);

natural_64_bit  num_bytes_to_store_bits(natural_64_bit const  num_bits_to_store);

template<typename T>
struct smallest_natural_type_storing_bit_count_of
{
    typedef typename typefn_if_then_else<8U * sizeof(T) <= 255U, natural_8_bit,
            typename typefn_if_then_else<8U * sizeof(T) <= 65535U, natural_16_bit,
            typename typefn_if_then_else<8U * sizeof(T) <= 4294967295U, natural_32_bit,
            natural_64_bit>::result >::result >::result     result;
};


#endif
