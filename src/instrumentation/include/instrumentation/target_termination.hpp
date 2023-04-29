#ifndef INSTRUMENTATION_TARGET_TERMINATION_HPP_INCLUDED
#   define INSTRUMENTATION_TARGET_TERMINATION_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>

namespace instrumentation {

enum class target_termination: natural_8_bit {
    normal,                             // Execution of benchmark's code finished normally.
    crash,                              // Benchmark's code crashed, e.g. division by zero, access outside allocated memory.
    timeout,                            // The target program timed out
    trace_max_length_reached,           // Trace is too long,
    br_instr_trace_max_length_reached,  // Trace of branching instructions is too long
    stdin_max_bytes_reached,            // Max amount of bytes were read from stdin
    max_stack_size_reached,             // Stack size reached maximum size
    num_types                           // To check for validity of a termination
};


static bool boundary_condition_violation(target_termination termination) {
    return target_termination::trace_max_length_reached <= termination && 
        termination <= target_termination::max_stack_size_reached;
}

static bool valid_termination(target_termination termination) {
    return termination < target_termination::num_types;
}


}

#endif


