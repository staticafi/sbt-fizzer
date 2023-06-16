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
        , bits{ nullptr }
        , trace{ nullptr }
        , mutated_bit_index{ invalid_stdin_bit_index }
        , leaf_branching{ nullptr }
        , execution_id{ 0 }
        , nodes{}
        , stoped_early{ false }
        , statistics{}
    {}

    bool  is_ready() const { return state == READY; }
    bool  is_busy() const { return state == BUSY; }

    void  start(stdin_bits_pointer  bits_ptr, execution_trace_pointer  trace_ptr,
                branching_node*  leaf_branching_ptr, natural_32_bit  execution_id_);
    void  stop();

    bool  generate_next_input(vecb&  bits_ref);
    void  process_execution_results(execution_trace_pointer  trace_ptr, branching_node*  entry_branching_ptr);

    branching_node*  get_leaf_branching() const { return leaf_branching; }
    std::unordered_set<branching_node*> const&  get_nodes_with_extended_sensitive_bits() { return nodes; }
    bool  get_stoped_early() const { return stoped_early; }

    performance_statistics const&  get_statistics() const { return statistics; }

private:

    STATE  state;
    stdin_bits_pointer  bits;
    execution_trace_pointer  trace;
    stdin_bit_index  mutated_bit_index;
    branching_node*  leaf_branching;
    natural_32_bit  execution_id;
    std::unordered_set<branching_node*>  nodes;
    bool  stoped_early;

    performance_statistics  statistics;
};


}

#endif
