#include <fuzzing/sensitivity_flow_analysis.hpp>
#include <fuzzing/progress_recorder.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>

namespace  fuzzing {


sensitivity_flow_analysis::sensitivity_flow_analysis(sala::Program const* const sala_program_ptr)
    : state{ READY }
    , program_ptr{ sala_program_ptr }
    , failures{}
    , trace{ nullptr }
    , node{ nullptr }
    , execution_id{ 0 }
    , changed_nodes{}
    , statistics{}
{}


void  sensitivity_flow_analysis::start(branching_node* const  node_ptr, natural_32_bit const  execution_id_)
{
    ASSUMPTION(is_ready() && !is_disabled());
    ASSUMPTION(node_ptr != nullptr && node_ptr->best_stdin && node_ptr->best_trace != nullptr);
    ASSUMPTION(node_ptr->best_trace->size() > node_ptr->get_trace_index());
    ASSUMPTION(
        [node_ptr]() -> bool {
            branching_node*  n = node_ptr;
            for (trace_index_type  i = n->get_trace_index() + 1U; i > 0U; --i, n = n->predecessor)
            {
                if (n == nullptr || n->id != node_ptr->best_trace->at(i - 1U).id)
                    return false;
                if (i > 1U && n->predecessor->successor_direction(n) != node_ptr->best_trace->at(i - 2U).direction)
                    return false;
            }
            return n == nullptr;
        }()
        );

    state = BUSY;
    trace = node_ptr->best_trace;
    node = node_ptr;
    execution_id = execution_id_;
    changed_nodes.clear();

    ++statistics.start_calls;
}


void  sensitivity_flow_analysis::compute_sensitive_bits()
{
    TMPROF_BLOCK();

    if (!is_busy() || is_disabled())
        return;


}


}
