#ifndef FUZZING_FUZZING_LOOP_HPP_INCLUDED
#   define FUZZING_FUZZING_LOOP_HPP_INCLUDED

#   include <fuzzing/termination_info.hpp>
#   include <fuzzing/analysis_outcomes.hpp>
#   include <fuzzing/execution_record.hpp>
#   include <fuzzing/execution_record_writer.hpp>
#   include <connection/benchmark_executor.hpp>
#   include <functional>

namespace  fuzzing {


analysis_outcomes  run(
        connection::benchmark_executor&  benchmark_executor,
        execution_record_writer&  save_execution_record,
        std::function<void(execution_record const&)> const&  collector_of_boundary_violations,
        fuzzing::termination_info const&  info,
        fuzzing::jetklee& jetklee
        );


}

#endif
