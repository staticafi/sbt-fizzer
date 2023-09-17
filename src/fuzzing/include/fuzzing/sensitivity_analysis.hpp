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

    sensitivity_analysis();

    bool  is_ready() const { return state == READY; }
    bool  is_busy() const { return state == BUSY; }

    void  start(branching_node*  node_ptr, natural_32_bit  execution_id_);
    void  stop();

    bool  generate_next_input(vecb&  bits_ref);
    void  process_execution_results(execution_trace_pointer  trace_ptr, branching_node*  entry_branching_ptr);

    branching_node*  get_node() const { return node; }
    std::unordered_set<branching_node*> const&  get_changed_nodes() { return changed_nodes; }
    bool  get_stopped_early() const { return stopped_early; }

    performance_statistics const&  get_statistics() const { return statistics; }

private:

    bool  is_mutated_bit_index_valid() const;
    bool  is_mutated_type_index_valid() const;
    bool  generate_next_typed_value(vecb&  bits_ref);

    template<typename T, int N>
    bool  write_bits(vecb&  bits_ref, T const  (&values)[N]);

    STATE  state;
    stdin_bits_and_types_pointer  bits_and_types;
    execution_trace_pointer  trace;
    stdin_bit_index  mutated_bit_index;
    natural_32_bit  mutated_type_index;
    natural_32_bit  mutated_value_index;
    stdin_bit_index  probed_bit_start_index;
    stdin_bit_index  probed_bit_end_index;
    branching_node*  node;
    natural_32_bit  execution_id;
    std::unordered_set<branching_node*>  changed_nodes;
    bool  stopped_early;

    performance_statistics  statistics;
};


}

#endif
