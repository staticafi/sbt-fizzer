#ifndef FUZZING_TERMINATION_INFO_HPP_INCLUDED
#   define FUZZING_TERMINATION_INFO_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>
#   include <limits>

namespace  fuzzing {


struct termination_info
{
    termination_info() : termination_info(std::numeric_limits<natural_32_bit>::max(), std::numeric_limits<natural_32_bit>::max()) {}
    termination_info(natural_32_bit const  max_executions_, natural_32_bit const  max_seconds_, bool const  allow_blind_fuzzing_ = false)
        : max_driver_executions(max_executions_)
        , max_fuzzing_seconds(max_seconds_)
        , allow_blind_fuzzing(allow_blind_fuzzing_)
    {}
    natural_32_bit  max_driver_executions;
    natural_32_bit  max_fuzzing_seconds;
    bool  allow_blind_fuzzing;
};


}

#endif
