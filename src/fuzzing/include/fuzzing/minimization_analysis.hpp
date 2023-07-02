#ifndef FUZZING_MINIMIZATION_ANALYSIS_HPP_INCLUDED
#   define FUZZING_MINIMIZATION_ANALYSIS_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <fuzzing/branching_node.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/math.hpp>
#   include <utility/random.hpp>
#   include <vector>
#   include <unordered_map>

namespace  fuzzing {


struct  minimization_analysis
{
    enum  STATE
    {
        READY,
        BUSY
    };

    struct  gradient_descent_state
    {
        enum STAGE {
            TAKE_NEXT_SEED,
            EXECUTE_SEED,
            STEP,
            PARTIALS,
            PARTIALS_EXTENDED,
        };
        
        STAGE  stage { TAKE_NEXT_SEED };
        vecb  bits;
        branching_function_value_type  value;
        vecf64  partials;
        vecf64  partials_extended;
        vecf64  bit_max_changes;
        vecu16  bit_order;
    };

    struct  performance_statistics
    {
        std::size_t  generated_inputs{ 0 };
        std::size_t  suppressed_repetitions{ 0 };
        std::size_t  max_bits{ 0 };
        std::size_t  seeds_processed{ 0 };
        std::size_t  gradient_steps{ 0 };
        std::size_t  start_calls{ 0 };
        std::size_t  stop_calls_regular{ 0 };
        std::size_t  stop_calls_early{ 0 };
    };

    minimization_analysis()
        : state{ READY }
        , node{ nullptr }
        , bits_and_types{ nullptr }
        , execution_id{ 0 }
        , path{}
        , bit_translation{}
        , seeds{}
        , descent{}
        , computed_input_stdin{}
        , hashes_of_generated_bits{}
        , random_generator{}
        , stopped_early{ false }
        , statistics{}
    {}

    bool  is_ready() const { return state == READY; }
    bool  is_busy() const { return state == BUSY; }

    void  start(branching_node*  node_ptr, stdin_bits_and_types_pointer  bits_ptr, natural_32_bit  execution_id_);
    void  stop();

    bool  generate_next_input(vecb&  bits_ref);
    void  process_execution_results(execution_trace_pointer  trace_ptr);

    branching_node*  get_node() const { return node; }
    bool  get_stopped_early() const { return stopped_early; }

    performance_statistics const&  get_statistics() const { return statistics; }

private:
    void  process_execution_results(branching_function_value_type  last_stdin_value);
    bool  apply_fast_execution_using_cache();

    STATE  state;
    branching_node*  node;
    stdin_bits_and_types_pointer  bits_and_types;
    natural_32_bit  execution_id;
    execution_path  path;
    vecu32  bit_translation;
    std::vector<vecb>  seeds;
    gradient_descent_state  descent;
    vecb  computed_input_stdin;
    std::unordered_map<std::size_t, branching_function_value_type> hashes_of_generated_bits;
    random_generator_for_natural_32_bit  random_generator;
    bool stopped_early;

    performance_statistics  statistics;
};


}

#endif
