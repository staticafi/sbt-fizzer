#ifndef FUZZING_STDIN_BITS_HPP_INCLUDED
#   define FUZZING_STDIN_BITS_HPP_INCLUDED

#   include <iomodels/stdin_base.hpp>
#   include <utility/math.hpp>
#   include <memory>
#   include <limits>

namespace  fuzzing {


using  stdin_bits_pointer = std::shared_ptr<vecb>;
using  stdin_bit_index = iomodels::stdin_base::bit_count_type;
static stdin_bit_index constexpr  invalid_stdin_bit_index{ std::numeric_limits<stdin_bit_index>::max() };


}

#endif
