#ifndef FUZZING_CHAIN_MINIMIZATION_ANALYSIS_HPP_INCLUDED
#   define FUZZING_CHAIN_MINIMIZATION_ANALYSIS_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <fuzzing/branching_node.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/math.hpp>
#   include <utility/random.hpp>
#   include <vector>
#   include <unordered_map>
#   include <unordered_set>

namespace  fuzzing {


struct  chain_minimization_analysis
{
    enum  STATE
    {
        READY,
        BUSY
    };

    enum PROGRESS_STAGE
    {
        PARTIALS,
        STEP,
        RECOVERY
    };

    union  typed_value_storage
    {
        typed_value_storage() : _uint64{ 0ULL } {}
        bool  _boolean;
        natural_8_bit  _uint8;
        integer_8_bit  _sint8;
        natural_16_bit  _uint16;
        integer_16_bit  _sint16;
        natural_32_bit  _uint32;
        integer_32_bit  _sint32;
        natural_64_bit  _uint64;
        integer_64_bit  _sint64;
        float_32_bit  _float32;
        float_64_bit  _float64;
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
        BRANCHING_PREDICATE  predicate{ BP_EQUAL };
        std::unordered_set<natural_32_bit>  variable_indices{};
    };

    struct  spatial_constraint
    {
        vecf64  normal{};
        float_64_bit  param{ 0.0 };
        BRANCHING_PREDICATE  predicate{ BP_EQUAL };
    };

    struct  local_space_of_branching
    {
        matf64  orthogonal_basis{};
        std::vector<spatial_constraint>  constraints{};
        std::vector<std::vector<natural_32_bit> >  variable_indices{};
        vecf64  gradient{};
        vecf64  sample_shift{};
        float_64_bit  sample_value{ 0.0 };
    };

    struct  gradient_step_result
    {
        stdin_bits_and_types_pointer  bits_and_types_ptr{ nullptr };
        std::vector<float_64_bit>  values{};
    };

    struct  divergence_recovery_props
    {
        PROGRESS_STAGE  stage_backup{ RECOVERY };
        vecf64  shift_backup{};
        float_64_bit  value_backup{ 0.0 };
        std::size_t  space_index{ std::numeric_limits<std::size_t>::max() };
        vecf64  shift_best{};
        float_64_bit  value_best{ std::numeric_limits<float_64_bit>::max() };
        std::vector<vecf64>  sample_shifts{};
    };

    struct  performance_statistics
    {
        std::size_t  generated_inputs{ 0 };
        std::size_t  partials{ 0 };
        std::size_t  gradient_steps{ 0 };
        std::size_t  start_calls{ 0 };
        std::size_t  stop_calls_regular{ 0 };
        std::size_t  stop_calls_early{ 0 };
        std::size_t  stop_calls_failed{ 0 };
    };

    static bool  are_types_of_sensitive_bits_available(
            stdin_bits_and_types_pointer  bits_and_types,
            std::unordered_set<stdin_bit_index> const&  sensitive_bits
            );

    chain_minimization_analysis();

    bool  is_disabled() const;
    bool  is_ready() const { return state == READY; }
    bool  is_busy() const { return state == BUSY; }

    bool  failed_on(branching_node const* const  node_) const { return failed_nodes.contains(node_); }

    void  start(branching_node*  node_ptr, stdin_bits_and_types_pointer  bits_and_types_ptr, natural_32_bit  execution_id_);
    void  stop();
    void  stop_with_failure();

    natural_32_bit  max_num_executions() const;

    bool  generate_next_input(vecb&  bits_ref);
    void  process_execution_results(execution_trace_pointer  trace_ptr, stdin_bits_and_types_pointer  bits_and_types_ptr);

    branching_node*  get_node() const { return node; }
    bool  get_stopped_early() const { return stopped_early; }

    performance_statistics const&  get_statistics() const { return statistics; }

private:

    bool  compute_shift_of_next_partial();
    void  compute_partial_derivative();
    void  transform_shift(std::size_t  src_space_index);
    void  insert_first_local_space();
    void  insert_next_local_space();
    bool  are_constraints_satisfied(std::vector<spatial_constraint> const&  constraints, vecf64 const&  shift) const;
    bool  clip_shift_by_constraints(
            std::vector<spatial_constraint> const&  constraints,
            vecf64 const&  gradient,
            vecf64&  shift,
            std::size_t  max_iterations = 10UL
            ) const;
    bool  compute_gradient_step_shifts();
    bool  __compute_gradient_step_shifts(
            std::vector<vecf64>&  resulting_shifts,
            local_space_of_branching const&  space,
            float_64_bit  value,
            BRANCHING_PREDICATE  predicate,
            vecf64 const*  shift_ptr = nullptr
            );
    bool  apply_best_gradient_step();
    void  load_origin(vecb const&  bits);
    void  store_shifted_origin(vecb&  bits);

    STATE  state;
    branching_node*  node;
    stdin_bits_and_types_pointer  bits_and_types;
    natural_32_bit  execution_id;
    std::vector<branching_info>  path;
    std::vector<mapping_to_input_bits>  from_variables_to_input;
    std::vector<type_of_input_bits>  types_of_variables;
    bool stopped_early;
    std::unordered_set<branching_node const*>  failed_nodes;
    natural_32_bit  num_executions;

    PROGRESS_STAGE  progress_stage;
    std::vector<typed_value_storage>  origin;
    vecf64  origin_in_reals;
    std::vector<local_space_of_branching>  local_spaces;
    std::vector<vecf64>  gradient_step_shifts;
    std::vector<gradient_step_result>  gradient_step_results;
    divergence_recovery_props  recovery;

    performance_statistics  statistics;
};


}

#endif
