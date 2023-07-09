#include <fuzzing/sensitivity_analysis.hpp>
#include <fuzzing/progress_recorder.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>

namespace  fuzzing {


void  sensitivity_analysis::start(branching_node* const  node_ptr, natural_32_bit const  execution_id_)
{
    ASSUMPTION(is_ready());
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
    bits_and_types = node_ptr->best_stdin;
    trace = node_ptr->best_trace;
    mutated_bit_index = 0;
    node = node_ptr;
    execution_id = execution_id_;
    nodes.clear();
    stopped_early = false;

    ++statistics.start_calls;
    statistics.max_bits = std::max(statistics.max_bits, (std::size_t)node->get_num_stdin_bits());

    recorder().on_sensitivity_start(node);
}


void  sensitivity_analysis::stop()
{
    if (!is_busy())
        return;

    if (mutated_bit_index < node->get_num_stdin_bits())
    {
        stopped_early = true;

        recorder().on_sensitivity_stop(progress_recorder::EARLY);

        ++statistics.stop_calls_early;
    }
    else
    {
        recorder().on_sensitivity_stop(progress_recorder::REGULAR);

        ++statistics.stop_calls_regular;
    }

    state = READY;
}


bool  sensitivity_analysis::generate_next_input(vecb&  bits_ref)
{
    TMPROF_BLOCK();

    if (!is_busy())
        return false;

    if (mutated_bit_index == node->get_num_stdin_bits())
    {
        for (branching_node* n = node; n != nullptr; n = n->predecessor)
        {
            n->sensitivity_performed = true;
            n->sensitivity_start_execution = execution_id;
        }

        stop();
        return false;
    }

    bits_ref = bits_and_types->bits;
    bits_ref.at(mutated_bit_index) = !bits_ref.at(mutated_bit_index);

    ++mutated_bit_index;

    ++statistics.generated_inputs;

    return true;
}


void  sensitivity_analysis::process_execution_results(execution_trace_pointer const  trace_ptr, branching_node* const  entry_branching_ptr)
{
    TMPROF_BLOCK();

    ASSUMPTION(is_busy());
    ASSUMPTION(trace_ptr != nullptr && entry_branching_ptr != nullptr);

    stdin_bit_index const low_bit_idx = ((mutated_bit_index - 1) / 8) * 8;
    branching_node*  n = entry_branching_ptr;
    for (trace_index_type  i = 0U, end = std::min(node->get_trace_index() + 1U, (trace_index_type)trace_ptr->size()); i < end; ++i)
    {
        branching_coverage_info const&  info_orig = trace->at(i);
        branching_coverage_info const&  info_curr = trace_ptr->at(i);

        INVARIANT(info_orig.id == info_curr.id && info_orig.id == n->id);

        if (info_orig.value != info_curr.value)
        {
            for (stdin_bit_index i = 0; i != 8; ++i)
            {
                auto const  it_and_state = n->sensitive_stdin_bits.insert(low_bit_idx + i);
                if (it_and_state.second)
                    nodes.insert(n);
            }
        }
        if (info_orig.direction != info_curr.direction)
            break;        
        n = n->successor(info_orig.direction).pointer;
    }
}


}
