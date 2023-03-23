#ifndef FUZZING_ANALYSIS_OUTCOMES_HPP_INCLUDED
#   define FUZZING_ANALYSIS_OUTCOMES_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <fuzzing/execution_record.hpp>
#   include <fuzzing/fuzzer.hpp>
#   include <utility/math.hpp>
#   include <vector>
#   include <string>
#   include <unordered_set>
#   include <unordered_map>

namespace  fuzzing {


struct analysis_outcomes
{
    enum struct TERMINATION_TYPE
    {
        NORMAL,
        SERVER_INTERNAL_ERROR,
        CLIENT_COMMUNICATION_ERROR,
        UNCLASSIFIED_ERROR
    };
    TERMINATION_TYPE  termination_type;
    std::string  termination_message;
    natural_32_bit  num_executions;
    long  num_elapsed_seconds;
    std::vector<location_id> covered_branchings;
    std::vector<branching_location_and_direction>  uncovered_branchings;
    std::vector<execution_record>  execution_records;
    sensitivity_analysis::performance_statistics   sensitivity_statistics;
    minimization_analysis::performance_statistics   minimization_statistics;
    jetklee_analysis::performance_statistics   jetklee_statistics;
    fuzzer::performance_statistics  statistics;
    std::unordered_map<std::string, std::string>  debug_data;
};


}

#endif
