#ifndef FUZZING_BRANCHING_NODE_HPP_INCLUDED
#   define FUZZING_BRANCHING_NODE_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <fuzzing/stdin_bits.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/math.hpp>
#   include <array>
#   include <unordered_set>

namespace  fuzzing {


using namespace instrumentation;


struct  branching_node
{
    struct  successor_pointer
    {
        enum LABEL
        {
            NOT_VISITED     = 0,    // pointer == nullptr
            END_EXCEPTIONAL = 1,    // pointer == nullptr
            END_NORMAL      = 2,    // pointer == nullptr
            VISITED         = 3     // pointer != nullptr
        };

        LABEL  label { NOT_VISITED };
        branching_node*  pointer { nullptr };
    };

    branching_node(
            location_id  id_,
            trace_index_type  trace_index_,
            branching_node*  predecessor_,
            stdin_bits_pointer  best_stdin_,
            execution_trace_pointer  best_trace_,
            branching_function_value_type  best_coverage_value_,
            branching_function_value_type  best_summary_value_
            )
        : id{ id_ }
        , trace_index{ trace_index_ }

        , predecessor{ predecessor_ }
        , successors{}

        , best_stdin{ best_stdin_ }
        , best_trace{ best_trace_ }
        , best_coverage_value{ best_coverage_value_ }
        , best_summary_value{ best_summary_value_ }

        , sensitivity_performed{ false }
        , minimization_performed{ false }

        , sensitive_stdin_bits{}
    {}

    successor_pointer const&  successor(bool const  direction) const { return direction == false ? successors.front() : successors.back(); }
    successor_pointer&  successor(bool const  direction) { return direction == false ? successors.front() : successors.back(); }

    bool  successor_direction(branching_node const* const  succ) const
    { ASSUMPTION(succ == successors.front().pointer || succ == successors.back().pointer);  return succ == successors.front().pointer ? false : true; }

    void  set_successor(bool const  direction, successor_pointer const&  succ)
    { ASSUMPTION(succ.pointer == nullptr || succ.label == successor_pointer::VISITED); successor(direction) = succ; }

    bool  is_did_branching() const { return sensitivity_performed && !sensitive_stdin_bits.empty(); }
    bool  is_iid_branching() const { return sensitivity_performed && sensitive_stdin_bits.empty(); }

    bool  is_direction_explored(bool const  direction) const
    { successor_pointer const&  succ = successor(direction); return succ.label == successor_pointer::VISITED || succ.label == successor_pointer::END_NORMAL; }

    location_id  id;
    trace_index_type  trace_index;

    branching_node*  predecessor;
    std::array<successor_pointer, 2>  successors;

    stdin_bits_pointer  best_stdin;
    execution_trace_pointer  best_trace;
    branching_function_value_type  best_coverage_value;
    branching_function_value_type  best_summary_value;

    bool sensitivity_performed;
    bool minimization_performed;

    std::unordered_set<stdin_bit_index>  sensitive_stdin_bits;
};


}

#endif