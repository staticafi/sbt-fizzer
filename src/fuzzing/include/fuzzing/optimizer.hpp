#ifndef FUZZING_OPTIMIZER_HPP_INCLUDED
#   define FUZZING_OPTIMIZER_HPP_INCLUDED

#   include <fuzzing/execution_record.hpp>
#   include <fuzzing/execution_record_writer.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <connection/benchmark_executor.hpp>
#   include <utility/math.hpp>
#   include <chrono>
#   include <functional>

namespace  fuzzing {


using namespace instrumentation;


struct optimization_outcomes;


struct  optimizer final
{
    struct  configuration
    {
        natural_32_bit  max_seconds{ 10 };
        natural_32_bit  max_trace_length{ 10000000 };
        natural_32_bit  max_stdin_bytes{ 18000000 };
    };

    enum struct TERMINATION_REASON
    {
        ALL_TESTS_WERE_PROCESSED,
        TIME_BUDGET_DEPLETED
    };

    struct  performance_statistics
    {
        natural_32_bit  num_executions{ 0 };
        natural_32_bit  num_seconds{ 0 };
        natural_32_bit  num_extended_tests{ 0 };
    };

    optimizer(configuration const&  cfg);

    natural_32_bit  num_remaining_seconds() const { return (natural_32_bit)config.max_seconds - get_elapsed_seconds(); }
    natural_32_bit  get_elapsed_seconds() const { return (natural_32_bit)std::chrono::duration_cast<std::chrono::seconds>(time_point_current - time_point_start).count(); }

    optimization_outcomes  run(
            std::vector<vecu8> const&  inputs_leading_to_boundary_violation,
            std::vector<location_id> const&  already_covered_branchings,
            std::vector<branching_location_and_direction> const&  already_uncovered_branchings,
            connection::benchmark_executor&  benchmark_executor,
            execution_record_writer&  save_execution_record
            );

    performance_statistics const&  get_statistics() const { return statistics; }

private:

    configuration  config;

    std::chrono::steady_clock::time_point  time_point_start;
    std::chrono::steady_clock::time_point  time_point_current;

    performance_statistics  statistics;
};


}

#endif
