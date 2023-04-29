#ifndef INSTRUMENTATION_TARGET_TERMINATION_HPP_INCLUDED
#   define INSTRUMENTATION_TARGET_TERMINATION_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>

namespace instrumentation {

enum class target_termination: natural_8_bit {
    normal,                       // Execution of benchmark's code finished normally.
    crash,                        // Benchmark's code crashed, e.g. division by zero, access outside allocated memory.
    timeout,                      // The target program timed out
    boundary_condition_violation, // Trace is too long, stack size reached maximum size, max amount of bytes were read from stdin, ...
    num_types                     // To check for validity of a termination
};

static bool valid_termination(target_termination termination) {
    return termination < target_termination::num_types;
}


}

#endif


