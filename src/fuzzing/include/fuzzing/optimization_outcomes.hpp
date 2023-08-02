#ifndef FUZZING_OPTIMIZATION_OUTCOMES_HPP_INCLUDED
#   define FUZZING_OPTIMIZATION_OUTCOMES_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <fuzzing/optimizer.hpp>
#   include <utility/math.hpp>
#   include <vector>
#   include <string>

namespace  fuzzing {


struct optimization_outcomes
{
    enum struct TERMINATION_TYPE
    {
        NORMAL,
        SERVER_INTERNAL_ERROR,
        CLIENT_COMMUNICATION_ERROR,
        UNCLASSIFIED_ERROR
    };

    TERMINATION_TYPE  termination_type;
    optimizer::TERMINATION_REASON  termination_reason; // Valid only if 'termination_type == NORMAL'.
    std::string  error_message; // Valid only if 'termination_type != NORMAL'.
    std::vector<location_id> covered_branchings;
    std::vector<branching_location_and_direction>  uncovered_branchings;
    optimizer::performance_statistics  statistics;
};


}

#endif
