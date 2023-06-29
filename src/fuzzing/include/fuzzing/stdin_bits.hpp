#ifndef FUZZING_STDIN_BITS_HPP_INCLUDED
#   define FUZZING_STDIN_BITS_HPP_INCLUDED

#   include <iomodels/stdin_base.hpp>
#   include <utility/math.hpp>
#   include <memory>
#   include <limits>

namespace  fuzzing {


struct  stdin_bits_and_types
{
    using vect = iomodels::stdin_base::input_types_vector;
    vecb  bits{};
    vect  types{};
};

using  stdin_bits_and_types_pointer = std::shared_ptr<stdin_bits_and_types>;
using  stdin_bit_index = natural_32_bit;
static stdin_bit_index constexpr  invalid_stdin_bit_index{ std::numeric_limits<stdin_bit_index>::max() };


}

#endif
