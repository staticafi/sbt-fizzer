#ifndef FUZZING_MINIMIZATION_ANALYSIS_HPP_INCLUDED
#   define FUZZING_MINIMIZATION_ANALYSIS_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <fuzzing/branching_node.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/math.hpp>
#   include <utility/random.hpp>
#   include <vector>
#   include <unordered_set>

namespace  fuzzing {


struct  minimization_analysis
{
    enum  STATE
    {
        READY,
        BUSY
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
        , bits{ nullptr }
        , path{}
        , bit_translation{}
        , seeds{}
        , descent{}
        , hashes_of_generated_bits{}
        , random_generator{}
        , stoped_early{ false }
        , statistics{}
    {}

    bool  is_ready() const { return state == READY; }
    bool  is_busy() const { return state == BUSY; }

    void  start(branching_node*  node_ptr, stdin_bits_pointer  bits_ptr);
    void  stop();

    bool  generate_next_input(vecb&  bits_ref);
    void  process_execution_results(execution_trace_pointer  trace_ptr);

    branching_node*  get_node() const { return node; }
    bool  get_stoped_early() const { return stoped_early; }

    performance_statistics const&  get_statistics() const { return statistics; }

private:

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

    STATE  state;
    branching_node*  node;
    stdin_bits_pointer  bits;
    execution_path  path;
    vecu32  bit_translation;
    std::vector<vecb>  seeds;
    gradient_descent_state  descent;
    std::unordered_set<std::size_t> hashes_of_generated_bits;
    random_generator_for_natural_32_bit  random_generator;
    bool stoped_early;

    performance_statistics  statistics;
};


}

#endif
