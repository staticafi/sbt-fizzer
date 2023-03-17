#ifndef FUZZING_FUZZING_LOOP_HPP_INCLUDED
#   define FUZZING_FUZZING_LOOP_HPP_INCLUDED

#   include <fuzzing/termination_info.hpp>
#   include <fuzzing/analysis_outcomes.hpp>
#   include <functional>

namespace  fuzzing {


analysis_outcomes  run(std::function<void()> const&  benchmark_executor, fuzzing::termination_info const&  info, bool  debug_mode = false);


}

#endif
