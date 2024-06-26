#ifndef FUZZING_SENSITIVITY_FLOW_ANALYSIS_HPP_INCLUDED
#   define FUZZING_SENSITIVITY_FLOW_ANALYSIS_HPP_INCLUDED

#   include <fuzzing/execution_trace.hpp>
#   include <fuzzing/branching_node.hpp>
#   include <sala/program.hpp>
#   include <unordered_set>

namespace  fuzzing {


struct  sensitivity_flow_analysis
{
    enum  STATE
    {
        READY,
        BUSY
    };

    struct  performance_statistics
    {
        std::size_t  start_calls{ 0 };
        std::size_t  stop_calls{ 0 };
        std::size_t  num_failures{ 0 };
        std::unordered_set<std::string>  errors{};
        std::unordered_set<std::string>  warnings{};
    };

    explicit sensitivity_flow_analysis(sala::Program const* sala_program_ptr);

    bool  is_disabled() const;
    bool  is_ready() const { return state == READY; }
    bool  is_busy() const { return state == BUSY; }

    bool failed_on(branching_node*  node_ptr) const { return failures.contains(node_ptr); }

    void  start(branching_node*  node_ptr, natural_32_bit  execution_id_);
    void  stop();
    void  compute_sensitive_bits();

    branching_node*  get_node() const { return node; }
    std::unordered_set<branching_node*> const&  get_changed_nodes() { return changed_nodes; }

    performance_statistics const&  get_statistics() const { return statistics; }

private:

    std::string  make_problem_message(std::string const&  content) const;

    struct input_flow;

    STATE  state;
    sala::Program const* program_ptr;
    std::unordered_set<branching_node*>  failures;
    execution_trace_pointer  trace;
    branching_node*  node;
    natural_32_bit  execution_id;
    std::unordered_set<branching_node*>  changed_nodes;

    performance_statistics  statistics;
};


}

#endif
