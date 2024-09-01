#include <fuzzing/sensitivity_analysis.hpp>
#include <fuzzing/progress_recorder.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>

namespace  fuzzing {


sensitivity_analysis::sensitivity_analysis()
    : state{ READY }
    , bits_and_types{ nullptr }
    , trace{ nullptr }
    , mutated_bit_index{ 0 }
    , probed_bit_start_index{ 0 }
    , probed_bit_end_index{ 0 }
    , node{ nullptr }
    , execution_id{ 0 }
    , changed_nodes{}
    , stopped_early{ false }
    , start_time{}
    , statistics{}
{}


bool  sensitivity_analysis::is_disabled() const
{
    return false;
}


bool  sensitivity_analysis::is_mutated_bit_index_valid() const
{
    return mutated_bit_index < node->get_num_stdin_bits();
}


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
    changed_nodes.clear();
    stopped_early = false;

    start_time = std::chrono::system_clock::now();

    ++statistics.start_calls;
    statistics.max_bits = std::max(statistics.max_bits, (std::size_t)node->get_num_stdin_bits());

    recorder().on_sensitivity_start(node);
}


void  sensitivity_analysis::stop()
{
    if (!is_busy())
        return;

    if (is_mutated_bit_index_valid())
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

    {
        std::pair<natural_32_bit,trace_index_type> const key{ node->get_trace_index(), node->get_num_stdin_bytes() };
        float_64_bit const  value = std::chrono::duration<float_64_bit>(std::chrono::system_clock::now() - start_time).count();
        //statistics.complexity[key].insert(value);
    }

    state = READY;
}


bool  sensitivity_analysis::generate_next_input(vecb&  bits_ref)
{
    TMPROF_BLOCK();

    if (!is_busy())
        return false;

    if (is_mutated_bit_index_valid())
    {
        stop();
        return false;
    }

    bits_ref = bits_and_types->bits;
    bits_ref.at(mutated_bit_index) = !bits_ref.at(mutated_bit_index);

    probed_bit_start_index = 8 * (mutated_bit_index / 8);
    probed_bit_end_index = probed_bit_start_index + 8;

    ++mutated_bit_index;

    ++statistics.generated_inputs;

    return true;
}


void  sensitivity_analysis::process_execution_results(execution_trace_pointer const  trace_ptr, branching_node* const  entry_branching_ptr)
{
    TMPROF_BLOCK();

    ASSUMPTION(is_busy());
    ASSUMPTION(trace_ptr != nullptr && entry_branching_ptr != nullptr);

    branching_node*  n = entry_branching_ptr;
    for (trace_index_type  i = 0U, end = std::min(node->get_trace_index() + 1U, (trace_index_type)trace_ptr->size()); i < end; ++i)
    {
        branching_coverage_info const&  info_orig = trace->at(i);
        branching_coverage_info const&  info_curr = trace_ptr->at(i);

        INVARIANT(info_orig.id == info_curr.id && info_orig.id == n->id);

        if (info_orig.value != info_curr.value)
            for (stdin_bit_index j = probed_bit_start_index, j_end = std::min(probed_bit_end_index, n->get_num_stdin_bits()); j < j_end; ++j)
            {
                auto const  it_and_state = n->sensitive_stdin_bits.insert(j);
                if (it_and_state.second)
                    changed_nodes.insert(n);
            }

        if (info_orig.direction != info_curr.direction)
            break;        
        n = n->successor(info_orig.direction).pointer;
    }
}


}
