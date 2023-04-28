#ifndef FUZZING_OPTIMIZER_HPP_INCLUDED
#   define FUZZING_OPTIMIZER_HPP_INCLUDED

#   include <fuzzing/analysis_outcomes.hpp>
#   include <fuzzing/execution_record.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/math.hpp>
#   include <chrono>

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

    optimizer(
        configuration const&  cfg,
        analysis_outcomes const&  fuzzing_outcomes_,
        std::function<void()> const&  benchmark_executor_,
        optimization_outcomes&  outcomes_
        );

    natural_32_bit  num_remaining_seconds() const { return (natural_32_bit)config.max_seconds - get_elapsed_seconds(); }
    natural_32_bit  get_elapsed_seconds() const { return (natural_32_bit)std::chrono::duration_cast<std::chrono::seconds>(time_point_current - time_point_start).count(); }

    void  run();

    performance_statistics const&  get_statistics() const { return statistics; }

private:

    configuration  config;
    std::function<void()> const&  benchmark_executor;
    analysis_outcomes const&  fuzzing_outcomes;

    std::chrono::steady_clock::time_point  time_point_start;
    std::chrono::steady_clock::time_point  time_point_current;

    optimization_outcomes&  outcomes;

    performance_statistics  statistics;
};


}

#endif
