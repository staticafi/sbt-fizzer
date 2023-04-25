#ifndef FUZZING_FUZZING_LOOP_HPP_INCLUDED
#   define FUZZING_FUZZING_LOOP_HPP_INCLUDED

#   include <fuzzing/termination_info.hpp>
#   include <fuzzing/analysis_outcomes.hpp>
#   include <functional>

namespace  fuzzing {


analysis_outcomes  run(std::function<void()> const&  benchmark_executor,
                       std::unique_ptr<connection::kleeient_connector>  kleeient_connector,
                       termination_info const&  info,
                       bool  debug_mode,
                       fuzzer::jetklee_usage  jetklee_usage_policy);


}

#endif
