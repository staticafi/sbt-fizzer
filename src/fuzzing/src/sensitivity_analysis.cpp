#include <fuzzing/sensitivity_analysis.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>

namespace  fuzzing {


void  sensitivity_analysis::start(
        stdin_bits_pointer const  bits_ptr,
        execution_trace_pointer const trace_ptr,
        branching_node* const  leaf_branching_ptr
        )
{
    ASSUMPTION(is_ready());
    ASSUMPTION(bits_ptr != nullptr && trace_ptr != nullptr && leaf_branching_ptr != nullptr);

    state = BUSY;
    bits = bits_ptr;
    trace = trace_ptr;
    mutated_bit_index = 0;
    leaf_branching = leaf_branching_ptr;
    nodes.clear();
    stoped_early = false;

    ++statistics.start_calls;
    statistics.max_bits = std::max(statistics.max_bits, bits->size());
}


void  sensitivity_analysis::stop()
{
    if (!is_busy())
        return;

    if (mutated_bit_index < bits->size())
    {
        stoped_early = true;

        ++statistics.stop_calls_early;
    }
    else
        ++statistics.stop_calls_regular;

    state = READY;
}


bool  sensitivity_analysis::generate_next_input(vecb&  bits_ref)
{
    TMPROF_BLOCK();

    if (!is_busy())
        return false;

    if (mutated_bit_index == bits->size())
    {
        auto  rit = trace->rbegin();
        branching_node* node = leaf_branching;
        while (node != nullptr)
        {
            INVARIANT(
                rit != trace->rend() && node->id == rit->id && (node->predecessor == nullptr) == (std::next(rit) == trace->rend()) &&
                (node->predecessor == nullptr || node->predecessor->successor_direction(node) == std::next(rit)->direction)
                );
            node->sensitivity_performed = true;
            node = node->predecessor;
            ++rit;
        }

        stop();
        return false;
    }

    bits_ref = *bits;
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

    branching_node*  node = entry_branching_ptr;
    auto  it_orig = trace->begin();
    auto  it_curr = trace_ptr->begin();
    while (node != nullptr && it_orig != trace->end() && it_curr != trace_ptr->end()
                && it_orig->id == it_curr->id && it_orig->id == node->id)
    {
        if (it_orig->value != it_curr->value)
        {
            auto const  it_and_state = node->sensitive_stdin_bits.insert(mutated_bit_index - 1);
            if (it_and_state.second)
                nodes.insert(node);
        }

        if (it_orig->direction != it_curr->direction)
            break;        

        node = node->successor(it_orig->direction).pointer;
        ++it_orig;
        ++it_curr;
    }
}


}
