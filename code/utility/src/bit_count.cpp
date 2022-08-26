#include <utility/bit_count.hpp>


natural_8_bit  compute_num_of_bits_to_store_number(natural_32_bit  number)
{
    natural_8_bit num_bits = 0U;
    do
    {
        number >>= 1U;
        ++num_bits;
    }
    while (number != 0U);
    return num_bits;
}

natural_8_bit  compute_byte_aligned_num_of_bits_to_store_number(natural_32_bit  number)
{
    natural_8_bit num_bits = compute_num_of_bits_to_store_number(number);
    while (num_bits % 8U != 0U)
        ++num_bits;
    return num_bits;
}

natural_64_bit  num_bytes_to_store_bits(natural_64_bit const  num_bits_to_store)
{
    return (num_bits_to_store >> 3U) + (((num_bits_to_store & 7U) == 0U) ? 0U : 1U);
}
