#ifndef FUZZING_BITFLIP_ANALYSIS_HPP_INCLUDED
#   define FUZZING_BITFLIP_ANALYSIS_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <fuzzing/branching_node.hpp>
#   include <utility/random.hpp>
#   include <unordered_set>

namespace  fuzzing {


struct  bitflip_analysis
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
    };

    bitflip_analysis();

    bool  is_ready() const { return state == READY; }
    bool  is_busy() const { return state == BUSY; }

    branching_node*  get_node() const { return node_ptr; }

    void  start(std::unordered_set<branching_node*> const&  leaf_branchings);
    void  stop();

    bool  generate_next_input(vecb&  bits_ref);

    performance_statistics const&  get_statistics() const { return statistics; }

private:

    bool  is_mutated_bit_index_valid() const;
    bool  is_mutated_type_index_valid() const;
    bool  generate_next_typed_value(vecb&  bits_ref);

    template<typename T, int N>
    bool  write_bits(vecb&  bits_ref, T const  (&values)[N]);

    STATE  state;
    branching_node*  node_ptr;
    stdin_bits_and_types_pointer  bits_and_types;
    stdin_bit_index  mutated_bit_index;
    natural_32_bit  mutated_type_index;
    natural_32_bit  mutated_value_index;
    stdin_bit_index  probed_bit_start_index;
    stdin_bit_index  probed_bit_end_index;
    std::unordered_set<stdin_bits_and_types const*>  processed_inputs;
    random_generator_for_natural_32_bit  rnd_generator;

    performance_statistics  statistics;
};


}

#endif
