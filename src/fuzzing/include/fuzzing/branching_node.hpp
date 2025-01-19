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

    using guid_type = natural_32_bit;

    branching_node(
            location_id  id_,
            trace_index_type  trace_index_,
            natural_32_bit  num_stdin_bytes_,
            branching_node*  predecessor_,
            stdin_bits_and_types_pointer  best_stdin_,
            execution_trace_pointer  best_trace_,
            br_instr_execution_trace_pointer  best_br_instr_trace_,
            branching_function_value_type  best_coverage_value_,
            branching_function_value_type  best_summary_value_,
            natural_32_bit  execution_number,
            bool  xor_like_branching_function_,
            BRANCHING_PREDICATE  branching_predicate_
            )
        : id{ id_ }
        , trace_index{ trace_index_ }
        , num_stdin_bytes{ num_stdin_bytes_ }

        , predecessor{ predecessor_ }
        , successors{}

        , best_stdin{ best_stdin_ }
        , best_trace{ best_trace_ }
        , best_br_instr_trace{ best_br_instr_trace_ }
        , best_coverage_value{ best_coverage_value_ }
        , best_summary_value{ best_summary_value_ }

        , sensitivity_performed{ false }
        , minimization_performed{ false }
        , bitshare_performed{ false }

        , sensitivity_start_execution{ std::numeric_limits<natural_32_bit>::max() }
        , minimization_start_execution{ std::numeric_limits<natural_32_bit>::max() }
        , bitshare_start_execution{ std::numeric_limits<natural_32_bit>::max() }
        , best_value_execution{ execution_number }

        , sensitive_stdin_bits{}

        , xor_like_branching_function{ xor_like_branching_function_ }
        , branching_predicate{ branching_predicate_ }

        , closed{ false }

        , max_successors_trace_index{ trace_index_ }
        , num_coverage_failure_resets{ 0U }

        , guid__{ get_fresh_guid__() }
    {}

    location_id const&  get_location_id() const { return id; }
    trace_index_type  get_trace_index() const { return trace_index; }
    natural_32_bit  get_num_stdin_bytes() const { return num_stdin_bytes; }
    natural_32_bit  get_num_stdin_bits() const { return 8U * num_stdin_bytes; }

    successor_pointer const&  successor(bool const  direction) const { return direction == false ? successors.front() : successors.back(); }
    successor_pointer&  successor(bool const  direction) { return direction == false ? successors.front() : successors.back(); }

    bool  successor_direction(branching_node const* const  succ) const
    { ASSUMPTION(succ == successors.front().pointer || succ == successors.back().pointer);  return succ == successors.front().pointer ? false : true; }

    void  set_successor(bool const  direction, successor_pointer const&  succ)
    { ASSUMPTION(succ.pointer == nullptr || succ.label == successor_pointer::VISITED); successor(direction) = succ; }

    bool  is_open_branching() const
    {
        return  (is_direction_unexplored(false) || is_direction_unexplored(true)) &&
                (!sensitivity_performed || (!sensitive_stdin_bits.empty() && (!bitshare_performed || !minimization_performed)));
    }
    bool  is_did_branching() const { return sensitivity_performed && !sensitive_stdin_bits.empty(); }
    bool  is_iid_branching() const { return sensitivity_performed && sensitive_stdin_bits.empty(); }

    bool  is_direction_explored(bool const  direction) const
    { successor_pointer const&  succ = successor(direction); return succ.label == successor_pointer::VISITED || succ.label == successor_pointer::END_NORMAL; }
    bool  is_direction_unexplored(bool const  direction) const { return successor(direction).label == successor_pointer::NOT_VISITED; }

    bool  is_closed() const { return closed; }
    void  set_closed(bool const  state = true) { closed = state; }

    int get_depth() const;

    guid_type  guid() const { return guid__; }

    location_id  id;
    trace_index_type  trace_index;
    natural_32_bit  num_stdin_bytes;

    branching_node*  predecessor;
    std::array<successor_pointer, 2>  successors;

    stdin_bits_and_types_pointer  best_stdin;
    execution_trace_pointer  best_trace;
    br_instr_execution_trace_pointer  best_br_instr_trace;
    branching_function_value_type  best_coverage_value;
    branching_function_value_type  best_summary_value;

    bool sensitivity_performed;
    bool minimization_performed;
    bool bitshare_performed;

    natural_32_bit  sensitivity_start_execution;
    natural_32_bit  minimization_start_execution;
    natural_32_bit  bitshare_start_execution;
    natural_32_bit  best_value_execution;

    std::unordered_set<stdin_bit_index>  sensitive_stdin_bits;

    bool  xor_like_branching_function;

    BRANCHING_PREDICATE  branching_predicate;

    bool  closed;

    trace_index_type  max_successors_trace_index;
    natural_32_bit  num_coverage_failure_resets;

private:
    guid_type  guid__;
    static guid_type  get_fresh_guid__();
};


}

#endif
