#ifndef FUZZING_BRANCHING_NODE_HPP_INCLUDED
#   define FUZZING_BRANCHING_NODE_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <fuzzing/stdin_bits.hpp>
#   include <fuzzing/number_overlay.hpp>
#   include <utility/sparse_data_types.hpp>
#   include <array>
#   include <vector>
#   include <unordered_set>

namespace  fuzzing {


struct  branching_node final
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

    struct  direction_coverage_props
    {
        enum PROGRESS_STAGE
        {
            PARTIALS,
            DESCENT,
            BIT_MUTATIONS,
            SPECIAL_VALUES
        };

        struct  mapping_to_input_bits
        {
            natural_32_bit  input_start_bit_index;
            std::vector<natural_8_bit>  value_bit_indices;
        };

        struct  branching_info
        {
            branching_node*  node_ptr{ nullptr };
            float_64_bit  value{ 0.0 };
            bool  direction{ false };
            comparator_type  predicate{ BP_EQUAL };
            bool  xor_like_branching_function{ false };
            std::unordered_set<natural_32_bit>  variable_indices{};
        };

        struct  spatial_constraint
        {
            sparse_vector  normal{};
            scalar  param{ 0.0 };
            comparator_type  predicate{ BP_EQUAL };
        };

        struct  local_space_of_branching
        {
            sparse_orthogonal_basis  orthogonal_basis{};
            std::vector<spatial_constraint>  constraints{};
            std::vector<std::vector<natural_32_bit> >  variable_indices{};
            sparse_orthogonal_basis  basis_vectors_in_world_space{};
            //vecf64  scales_of_basis_vectors_in_world_space{};
            sparse_vector  gradient{};
            mutable sparse_vector  sample_shift{};
            mutable scalar  sample_value{ 0.0 };
        };

        struct  partials_stage_props
        {
            void clear() { *this = {}; }
            std::vector<sparse_vector>  shifts{};
        };

        direction_coverage_props();

        stdin_bits_and_types_pointer  bits_and_types;
        natural_32_bit  execution_id;
        std::vector<branching_info>  path;
        std::vector<mapping_to_input_bits>  from_variables_to_input;
        type_vector  types_of_variables;
        natural_32_bit  num_executions;
        natural_32_bit  max_executions;

        PROGRESS_STAGE  progress_stage;
        sparse_vector  origin;
        // origin_set  tested_origins;
        std::vector<local_space_of_branching>  local_spaces;
        partials_stage_props  partials_props;
        // gradient_descent_props  descent_props;
    };

    using guid_type = natural_32_bit;

    branching_node(
            location_id  id_,
            trace_index_type  trace_index_,
            natural_32_bit  num_stdin_bytes_,
            bool  xor_like_branching_function_,
            BRANCHING_PREDICATE  branching_predicate_,
            branching_node*  predecessor_,
            stdin_bits_and_types_pointer  best_stdin_,
            execution_trace_pointer  best_trace_,
            br_instr_execution_trace_pointer  best_br_instr_trace_,
            natural_32_bit  execution_number
            );

    location_id const&  get_location_id() const { return id; }
    trace_index_type  get_trace_index() const { return trace_index; }
    natural_32_bit  get_num_stdin_bytes() const { return num_stdin_bytes; }
    natural_32_bit  get_num_stdin_bits() const { return 8U * num_stdin_bytes; }
    bool  get_xor_like_branching_function() const { return xor_like_branching_function; }
    BRANCHING_PREDICATE  get_branching_predicate() const { return branching_predicate; }

    branching_node*  get_predecessor() const { return predecessor; }
    successor_pointer const&  successor(bool const  direction) const { return direction == false ? successors.front() : successors.back(); }
    successor_pointer&  successor(bool const  direction) { return direction == false ? successors.front() : successors.back(); }

    bool  successor_direction(branching_node const* const  succ) const
    { ASSUMPTION(succ == successors.front().pointer || succ == successors.back().pointer);  return succ == successors.front().pointer ? false : true; }

    void  set_successor(bool const  direction, successor_pointer const&  succ)
    { ASSUMPTION(succ.pointer == nullptr || succ.label == successor_pointer::VISITED); successor(direction) = succ; }

    bool  is_direction_unexplored(bool const  direction) const { return successor(direction).label == successor_pointer::NOT_VISITED; }

    stdin_bits_and_types_pointer  get_best_stdin() const { return best_stdin; }
    execution_trace_pointer  get_best_trace() const { return best_trace; }
    br_instr_execution_trace_pointer  get_best_br_instr_trace() const { return best_br_instr_trace; }
    branching_function_value_type  get_best_value() const { return best_trace->at(trace_index).value; }

    void  update_best_data(
            stdin_bits_and_types_pointer  stdin_,
            execution_trace_pointer  trace_,
            br_instr_execution_trace_pointer  br_instr_trace_,
            natural_32_bit  execution_id_
            );
    void  release_coverage_data();

    bool  was_sensitivity_performed() const { return sensitivity_performed; }
    bool  was_bitshare_performed() const { return bitshare_performed; }
    bool  was_coverage_performed() const { return coverage_performed; }
    bool  is_closed() const { return closed; }
    bool  is_open_branching() const
    {
        return  (is_direction_unexplored(false) || is_direction_unexplored(true)) &&
                (!sensitivity_performed || (!sensitive_stdin_bits.empty() && (!bitshare_performed || !coverage_performed)));
    }
    void  set_closed(bool const  state = true) { closed = state; }
    bool  is_iid_branching() const { return sensitivity_performed && sensitive_stdin_bits.empty(); }

    natural_32_bit  get_sensitivity_start_execution() const { return sensitivity_start_execution; }
    natural_32_bit  get_bitshare_start_execution() const { return bitshare_start_execution; }
    natural_32_bit  get_coverage_start_execution() const { return coverage_start_execution; }
    natural_32_bit  get_best_value_execution() const { return best_value_execution; }

    void  set_sensitivity_performed(natural_32_bit  execution_id);
    void  set_bitshare_performed(natural_32_bit  execution_id);
    void  set_coverage_performed(natural_32_bit  execution_id);

    std::unordered_set<stdin_bit_index> const&  get_sensitive_stdin_bits() const { return sensitive_stdin_bits; }
    bool  insert_sensitive_stdin_bit(stdin_bit_index const  idx) { return sensitive_stdin_bits.insert(idx).second; }
    direction_coverage_props*  get_coverage_props() { return coverage_props.get(); }

    trace_index_type  get_max_successors_trace_index() const { return max_successors_trace_index; }
    void  set_max_successors_trace_index(trace_index_type const  idx) { max_successors_trace_index = idx; }

    natural_32_bit  get_num_coverage_failure_resets() const { return num_coverage_failure_resets; }
    void  perform_failure_reset();

    guid_type  guid() const { return guid__; }

private:

    location_id  id;
    trace_index_type  trace_index;
    natural_32_bit  num_stdin_bytes;
    bool  xor_like_branching_function;
    BRANCHING_PREDICATE  branching_predicate;

    branching_node*  predecessor;
    std::array<successor_pointer, 2>  successors;

    stdin_bits_and_types_pointer  best_stdin;
    execution_trace_pointer  best_trace;
    br_instr_execution_trace_pointer  best_br_instr_trace;

    bool  sensitivity_performed;
    bool  bitshare_performed;
    bool  coverage_performed;
    bool  closed;

    natural_32_bit  sensitivity_start_execution;
    natural_32_bit  bitshare_start_execution;
    natural_32_bit  coverage_start_execution;
    natural_32_bit  best_value_execution;

    std::unordered_set<stdin_bit_index>  sensitive_stdin_bits;
    std::unique_ptr<direction_coverage_props>  coverage_props;

    trace_index_type  max_successors_trace_index;
    natural_32_bit  num_coverage_failure_resets;

    guid_type  guid__;
    static guid_type  get_fresh_guid__();
};


}

#endif
