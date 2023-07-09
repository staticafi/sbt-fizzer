#ifndef FUZZING_SENSITIVITY_ANALYSIS_HPP_INCLUDED
#   define FUZZING_SENSITIVITY_ANALYSIS_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <fuzzing/branching_node.hpp>
#   include <unordered_set>

namespace  fuzzing {


struct  sensitivity_analysis
{
    enum  STATE
    {
        READY,
        BUSY
    };

    struct  performance_statistics
    {
        std::size_t  generated_inputs{ 0 };
        std::size_t  max_bits{ 0 };
        std::size_t  start_calls{ 0 };
        std::size_t  stop_calls_regular{ 0 };
        std::size_t  stop_calls_early{ 0 };
    };

    sensitivity_analysis()
        : state{ READY }
        , bits_and_types{ nullptr }
        , trace{ nullptr }
        , mutated_bit_index{ invalid_stdin_bit_index }
        , node{ nullptr }
        , execution_id{ 0 }
        , nodes{}
        , stopped_early{ false }
        , statistics{}
    {}

    bool  is_ready() const { return state == READY; }
    bool  is_busy() const { return state == BUSY; }

    void  start(branching_node*  node_ptr, natural_32_bit  execution_id_);
    void  stop();

    bool  generate_next_input(vecb&  bits_ref);
    void  process_execution_results(execution_trace_pointer  trace_ptr, branching_node*  entry_branching_ptr);

    branching_node*  get_node() const { return node; }
    std::unordered_set<branching_node*> const&  get_nodes_with_extended_sensitive_bits() { return nodes; }
    bool  get_stopped_early() const { return stopped_early; }

    performance_statistics const&  get_statistics() const { return statistics; }

private:

    STATE  state;
    stdin_bits_and_types_pointer  bits_and_types;
    execution_trace_pointer  trace;
    stdin_bit_index  mutated_bit_index;
    branching_node*  node;
    natural_32_bit  execution_id;
    std::unordered_set<branching_node*>  nodes;
    bool  stopped_early;

    performance_statistics  statistics;
};


}

#endif
