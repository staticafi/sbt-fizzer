#include <fuzzing/branching_node.hpp>
#include <utility/assumptions.hpp>

namespace  fuzzing {


branching_node::branching_node(
        location_id const  id_,
        trace_index_type const  trace_index_,
        natural_32_bit const  num_stdin_bytes_,
        bool const  xor_like_branching_function_,
        BRANCHING_PREDICATE const  branching_predicate_,
        branching_node* const  predecessor_,
        stdin_bits_and_types_pointer const  best_stdin_,
        execution_trace_pointer const  best_trace_,
        br_instr_execution_trace_pointer const  best_br_instr_trace_,
        natural_32_bit const  execution_number
        )
    : id{ id_ }
    , trace_index{ trace_index_ }
    , num_stdin_bytes{ num_stdin_bytes_ }
    , xor_like_branching_function{ xor_like_branching_function_ }
    , branching_predicate{ branching_predicate_ }

    , predecessor{ predecessor_ }
    , successors{}

    , best_stdin{ best_stdin_ }
    , best_trace{ best_trace_ }
    , best_br_instr_trace{ best_br_instr_trace_ }

    , sensitive_stdin_bits{}

    , sensitivity_performed{ false }
    , local_search_performed{ false }
    , closed{ false }

    , sensitivity_start_execution{ std::numeric_limits<natural_32_bit>::max() }
    , local_search_start_execution{ std::numeric_limits<natural_32_bit>::max() }
    , best_value_execution{ execution_number }

    , max_successors_trace_index{ trace_index_ }
    , num_coverage_failure_resets{ 0U }

    , guid__{ get_fresh_guid__() }
{}


void  branching_node::update_best_data(
        stdin_bits_and_types_pointer const  stdin_,
        execution_trace_pointer const  trace_,
        br_instr_execution_trace_pointer const  br_instr_trace_,
        natural_32_bit const  execution_id_
        )
{
    best_stdin = stdin_;
    best_trace = trace_;
    best_br_instr_trace = br_instr_trace_;
    best_value_execution = execution_id_;
}


void  branching_node::release_best_data(bool const  also_sensitive_bits)
{
    best_stdin = nullptr;
    best_trace = nullptr;
    best_br_instr_trace = nullptr;
    if (also_sensitive_bits)
        sensitive_stdin_bits.clear();
}


void  branching_node::set_sensitivity_performed(natural_32_bit  execution_id)
{
    sensitivity_performed = true;
    sensitivity_start_execution = execution_id;
}


void  branching_node::set_bitshare_performed(natural_32_bit  execution_id)
{
    bitshare_performed = true;
    bitshare_start_execution = execution_id;
}


void  branching_node::set_local_search_performed(natural_32_bit  execution_id)
{
    local_search_performed = true;
    local_search_start_execution = execution_id;
}


void  branching_node::perform_failure_reset()
{
    bitshare_performed = false;
    local_search_performed = false;
    bitshare_start_execution = std::numeric_limits<natural_32_bit>::max();
    local_search_start_execution = std::numeric_limits<natural_32_bit>::max();
    closed = false;
    ++num_coverage_failure_resets;
}


branching_node::guid_type  branching_node::get_fresh_guid__()
{
    static guid_type  fresh_guid_counter{ 0U };
    guid_type const  result{ ++fresh_guid_counter };
    ASSUMPTION(result != 0);
    return result;
}


}
