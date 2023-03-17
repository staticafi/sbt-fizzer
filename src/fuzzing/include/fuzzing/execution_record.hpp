#ifndef FUZZING_EXECUTION_RECORD_HPP_INCLUDED
#   define FUZZING_EXECUTION_RECORD_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <utility/math.hpp>

namespace  fuzzing {


struct  execution_record
{
    using execution_flags = natural_8_bit;

    static execution_flags constexpr  BRANCH_DISCOVERED   = 1 << 0;
    static execution_flags constexpr  BRANCH_COVERED      = 1 << 1;
    static execution_flags constexpr  EXECUTION_CRASHES   = 1 << 2;

    execution_flags  flags { 0 }; 
    vecb  stdin_bits {};
    vecu8  stdin_bit_counts {};
    execution_path  path {};
};


}

#endif
