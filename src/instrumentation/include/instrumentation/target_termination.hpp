#ifndef INSTRUMENTATION_TARGET_TERMINATION_HPP_INCLUDED
#   define INSTRUMENTATION_TARGET_TERMINATION_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>

namespace instrumentation {

enum class target_termination: natural_8_bit {
    normal                          = 0, // Execution of benchmark's code finished normally.
    crash                           = 1, // Benchmark's code crashed, e.g. division by zero, access outside allocated memory.
    timeout                         = 2, // The target program timed out
    boundary_condition_violation    = 3, // Trace is too long, stack size reached maximum size, max amount of bytes were read from stdin, ...
    medium_overflow                 = 4  // The communication medium (e.g., shared memory) cannot accept more bytes.
};

static bool valid_termination(target_termination termination) {
    return termination <= target_termination::medium_overflow;
}


}

#endif


