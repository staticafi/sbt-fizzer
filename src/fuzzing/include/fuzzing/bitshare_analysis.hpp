#ifndef FUZZING_BITSHARE_ANALYSIS_HPP_INCLUDED
#   define FUZZING_BITSHARE_ANALYSIS_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <fuzzing/branching_node.hpp>
#   include <unordered_map>
#   include <array>
#   include <deque>


namespace  fuzzing {


struct  bitshare_analysis
{
    enum  STATE
    {
        READY,
        BUSY
    };

    struct  performance_statistics
    {
        std::size_t  generated_inputs{ 0 };
        std::size_t  hits{ 0 };
        std::size_t  misses{ 0 };
        std::size_t  start_calls{ 0 };
        std::size_t  stop_calls_regular{ 0 };
        std::size_t  stop_calls_early{ 0 };
        std::size_t  stop_calls_instant{ 0 };
        std::size_t  num_locations{ 0 };
        std::size_t  num_insertions{ 0 };
        std::size_t  num_deletions{ 0 };
    };

    bitshare_analysis();

    bool  is_ready() const { return state == READY; }
    bool  is_busy() const { return state == BUSY; }

    branching_node*  get_node() const { return processed_node; }

    void  start(branching_node*  node_ptr);
    void  stop();

    bool  generate_next_input(vecb&  bits_ref);
    void  process_execution_results(execution_trace_pointer  trace_ptr);

    void  bits_available_for_branching(branching_node*  node_ptr, execution_trace_pointer  trace, stdin_bits_pointer  stdin_bits);

    performance_statistics const&  get_statistics() const { return statistics; }

private:

    static constexpr std::size_t  max_deque_size = 10;

    STATE  state;
    std::unordered_map<location_id::id_type, std::array<std::deque<vecb>, 2> >  cache;
    branching_node*  processed_node;
    std::deque<vecb>*  samples_ptr;
    std::size_t  sample_index;
    performance_statistics  statistics;
};


}

#endif
