#ifndef FUZZING_TYPED_MINIMIZATION_ANALYSIS_HPP_INCLUDED
#   define FUZZING_TYPED_MINIMIZATION_ANALYSIS_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <fuzzing/branching_node.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/math.hpp>
#   include <utility/random.hpp>
#   include <vector>
#   include <unordered_map>

namespace  fuzzing {


struct  typed_minimization_analysis
{
    enum  STATE
    {
        READY,
        BUSY
    };

    enum PROGRESS_STAGE
    {
        SEED,
        PARTIALS,
        STEP
    };

    union  value_of_variable
    {
        bool  value_boolean;

        natural_8_bit  value_uint8;
        integer_8_bit  value_sint8;

        natural_16_bit  value_uint16;
        integer_16_bit  value_sint16;

        natural_32_bit  value_uint32;
        integer_32_bit  value_sint32;

        natural_64_bit  value_uint64;
        integer_64_bit  value_sint64;

        float_32_bit  value_float32;
        float_64_bit  value_float64;
    };

    struct  mapping_to_input_bits
    {
        natural_32_bit  input_start_bit_index;
        std::vector<natural_8_bit>  value_bit_indices;
    };

    struct  performance_statistics
    {
        std::size_t  generated_inputs{ 0 };
        std::size_t  max_bits{ 0 };
        std::size_t  seeds_processed{ 0 };
        std::size_t  gradient_steps{ 0 };
        std::size_t  start_calls{ 0 };
        std::size_t  stop_calls_regular{ 0 };
        std::size_t  stop_calls_early{ 0 };
    };

    static bool  are_types_of_sensitive_bits_available(
            stdin_bits_and_types_pointer  bits_and_types,
            std::unordered_set<stdin_bit_index> const&  sensitive_bits
            );

    typed_minimization_analysis();

    bool  is_ready() const { return state == READY; }
    bool  is_busy() const { return state == BUSY; }

    void  start(branching_node*  node_ptr, stdin_bits_and_types_pointer  bits_and_types_ptr, natural_32_bit  execution_id_);
    void  stop();

    bool  generate_next_input(vecb&  bits_ref);
    void  process_execution_results(execution_trace_pointer  trace_ptr);

    branching_node*  get_node() const { return node; }
    bool  get_stoped_early() const { return stoped_early; }

    performance_statistics const&  get_statistics() const { return statistics; }

private:
    void  generate_next_seed();
    void  generate_next_partial();

    void  compute_step_variables();
    void  compute_current_variable_and_function_value_from_step();

    void  write_variable_values_to_input(vecb&  bits_ref);

    branching_function_value_type  process_execution_trace(execution_trace_pointer  trace_ptr);

    STATE  state;
    branching_node*  node;
    stdin_bits_and_types_pointer  bits_and_types;
    natural_32_bit  execution_id;
    execution_path  path;
    std::vector<mapping_to_input_bits>  from_variables_to_input;
    std::vector<type_of_input_bits>  types_of_variables;

    PROGRESS_STAGE  progress_stage;
    std::vector<value_of_variable>  current_variable_values;
    branching_function_value_type  current_fuction_value;
    std::vector<value_of_variable>  partial_variable_values;
    std::vector<branching_function_value_type>  partial_fuction_values;
    std::vector<natural_32_bit>  step_variable_indices;
    std::vector<value_of_variable>  step_variable_values;
    std::vector<branching_function_value_type>  step_fuction_values;

    std::vector<value_of_variable>  executed_variable_values;

    bool stoped_early;

    random_generator_for_natural_32_bit  random_generator32;
    random_generator_for_natural_64_bit  random_generator64;

    performance_statistics  statistics;
};


}

#endif