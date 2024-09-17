#ifndef FUZZING_ANALYSIS_OUTCOMES_HPP_INCLUDED
#   define FUZZING_ANALYSIS_OUTCOMES_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
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

    struct output_statistics
    {
        natural_32_bit  num_generated_tests{ 0U };
        natural_32_bit  num_crashes{ 0U };
        natural_32_bit  num_boundary_violations{ 0U };
    };

    TERMINATION_TYPE  termination_type{ TERMINATION_TYPE::NORMAL };
    fuzzer::TERMINATION_REASON  termination_reason{ // Valid only if 'termination_type == NORMAL'.
        fuzzer::TERMINATION_REASON::ALL_REACHABLE_BRANCHINGS_COVERED
        };
    std::string  error_message{}; // Valid only if 'termination_type != NORMAL'.
    natural_32_bit  num_executions{ 0U };
    float_64_bit  num_elapsed_seconds{ 0.0 };
    std::vector<location_id> covered_branchings{};
    std::vector<branching_location_and_direction>  uncovered_branchings{};
    input_flow_analysis::performance_statistics   input_flow_statistics{};
    sensitivity_analysis::performance_statistics   sensitivity_statistics{};
    typed_minimization_analysis::performance_statistics   typed_minimization_statistics{};
    minimization_analysis::performance_statistics   minimization_statistics{};
    bitshare_analysis::performance_statistics   bitshare_statistics{};
    fuzzer::performance_statistics  fuzzer_statistics{};
    std::unordered_map<std::string, output_statistics>  output_statistics{};
};


}

#endif
