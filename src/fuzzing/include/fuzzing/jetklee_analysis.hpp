#ifndef FUZZING_JETKLEE_ANALYSIS_HPP_INCLUDED
#   define FUZZING_JETKLEE_ANALYSIS_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <fuzzing/branching_node.hpp>
#   include <connection/kleeient_connector.hpp>
#   include <unordered_set>

namespace  fuzzing {


struct  jetklee_analysis
{
    enum  STATE
    {
        READY,
        BUSY
    };

    struct  performance_statistics
    {
        std::size_t  generated_inputs{ 0 };
        std::size_t  start_calls{ 0 };
        std::size_t  covered_branchings{ 0 };
    };

    jetklee_analysis(std::unique_ptr<connection::kleeient_connector> kleeient_connector);

    bool  is_ready() const { return state == READY; }
    bool  is_busy() const { return state == BUSY; }

    branching_node*  get_node() const { return node_ptr; }

    bool  is_worth_processing(branching_node*  tested_node_ptr) const;

    void  start(branching_node*  node_ptr_);
    void  stop();

    bool  generate_next_input(vecb&  bits_ref);
    void  process_execution_results(execution_trace_pointer  trace_ptr);

    performance_statistics const&  get_statistics() const { return statistics; }

private:

    STATE  state;
    branching_node*  node_ptr;
    bool  direction;
    std::unique_ptr<connection::kleeient_connector>  kleeient_connector;
    bool  flipped_last_branching;
    bool  kept_last_branching;
    performance_statistics  statistics;

    std::vector<bool>  prepare_trace(branching_node *node);
};


}

#endif
