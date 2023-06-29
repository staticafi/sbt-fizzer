#ifndef FUZZING_STDIN_BITS_HPP_INCLUDED
#   define FUZZING_STDIN_BITS_HPP_INCLUDED

#   include <iomodels/stdin_base.hpp>
#   include <utility/math.hpp>
#   include <memory>
#   include <limits>

namespace  fuzzing {


struct  stdin_bits_and_types
{
    using  type_of_input_bits = iomodels::stdin_base::type_of_input_bits;
    using  vect = iomodels::stdin_base::input_types_vector;

    stdin_bits_and_types(vecu8 const&  bytes_, vect const&  types_);

    natural_32_bit  type_index(natural_32_bit  bit_index) const;
    natural_32_bit  type_start_bit_index(natural_32_bit const  type_index) const
    { return type_end_bit_index(type_index) + 1U - num_bits(types.at(type_index)); }
    natural_32_bit  type_end_bit_index(natural_32_bit const type_index) const { return bit_end_indices_of_types.at(type_index); }

    type_of_input_bits  type_of_bit(natural_32_bit const  bit_index) const { return types.at(type_index(bit_index)); }

    vecb  bits;
    vect  types;
    vecu32  bit_end_indices_of_types;
};

using  stdin_bits_and_types_pointer = std::shared_ptr<stdin_bits_and_types>;
using  stdin_bit_index = natural_32_bit;
static stdin_bit_index constexpr  invalid_stdin_bit_index{ std::numeric_limits<stdin_bit_index>::max() };


}

#endif
