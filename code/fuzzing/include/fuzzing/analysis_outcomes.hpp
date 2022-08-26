#ifndef FUZZING_ANALYSIS_OUTCOMES_HPP_INCLUDED
#   define FUZZING_ANALYSIS_OUTCOMES_HPP_INCLUDED

#   include <instrumentation/instrumentation_types.hpp>
#   include <vector>
#   include <string>
#   include <unordered_set>

namespace  fuzzing {


using  branching_location_and_direction = std::pair<instrumentation::location_id, bool>;


struct  trace_with_coverage_info
{
    std::vector<bool>  input_stdin;
    std::vector<natural_8_bit>  input_stdin_counts;
    std::vector<branching_location_and_direction>  trace;
    std::unordered_set<instrumentation::location_id>  discovered_locations;
    std::unordered_set<instrumentation::location_id>  covered_locations;
};


struct analysis_outcomes
{
    enum struct TERMINATION_TYPE
    {
        NORMAL,
        INVARIANT_FAILURE,
        ASSUMPTION_FAILURE,
        CODE_UNDER_CONSTRUCTION_REACHED,
        UNCLASSIFIED_EXCEPTION
    };
    TERMINATION_TYPE  termination_type;
    std::string  termination_message;
    natural_32_bit  num_executions;
    long  num_elapsed_seconds;
    std::vector<instrumentation::location_id> covered_branchings;
    std::vector<branching_location_and_direction>  uncovered_branchings;
    std::vector<trace_with_coverage_info>  traces_forming_coverage;
};


}

#endif
