#ifndef FUZZING_EXECUTION_RECORD_HPP_INCLUDED
#   define FUZZING_EXECUTION_RECORD_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <utility/math.hpp>

namespace  fuzzing {


struct  execution_record
{
    using execution_flags = natural_8_bit;
    using input_types_vector = std::vector<type_of_input_bits>;

    static execution_flags constexpr  BRANCH_DISCOVERED   = 1 << 0;
    static execution_flags constexpr  BRANCH_COVERED      = 1 << 1;
    static execution_flags constexpr  EXECUTION_CRASHES   = 1 << 2;
    static execution_flags constexpr  BOUNDARY_CONDITION_VIOLATION = 1 << 3;

    execution_flags  flags { 0 }; 
    vecu8  stdin_bytes {};
    input_types_vector  stdin_types {};
    execution_path  path {};
};


}

#endif
