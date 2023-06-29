#include <fuzzing/stdin_bits.hpp>
#include <algorithm>

namespace  fuzzing {


stdin_bits_and_types::stdin_bits_and_types(vecu8 const&  bytes_, vect const&  types_)
    : bits{}
    , types{ types_ }
    , bit_end_indices_of_types{}
{
    bytes_to_bits(bytes_, bits);
    natural_32_bit  idx = 0U;
    bit_end_indices_of_types.reserve(types.size());
    for (type_of_input_bits  type : types)
    {
        idx += num_bits(type);
        bit_end_indices_of_types.push_back(idx - 1U);
    }
    ASSUMPTION(idx == bits.size());
}


natural_32_bit  stdin_bits_and_types::type_index(natural_32_bit const  bit_index) const
{
    ASSUMPTION(bit_index < (natural_32_bit)bits.size());
    return std::distance(
                bit_end_indices_of_types.begin(),
                std::lower_bound(
                        bit_end_indices_of_types.begin(),
                        bit_end_indices_of_types.end(),
                        bit_index
                        )
                );
}


}
