#ifndef FUZZING_TERMINATION_INFO_HPP_INCLUDED
#   define FUZZING_TERMINATION_INFO_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>

namespace  fuzzing {


struct termination_info
{
    natural_32_bit  max_executions{ 1000000 };
    natural_32_bit  max_seconds{ 900 }; // 15min
};


}

#endif
