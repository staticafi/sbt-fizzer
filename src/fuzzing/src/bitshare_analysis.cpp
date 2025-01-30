#include <fuzzing/bitshare_analysis.hpp>
#include <fuzzing/progress_recorder.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>

namespace  fuzzing {


bitshare_analysis::bitshare_analysis()
    : state{ READY }
    , cache{}
    , processed_node{ nullptr }
    , samples_ptr{ nullptr }
    , sample_index{ 0 }
    , statistics{}
{}

void  bitshare_analysis::start(branching_node*  node_ptr, natural_32_bit const  execution_id_)
{
    ASSUMPTION(is_ready());
    ASSUMPTION(node_ptr != nullptr && node_ptr->get_best_stdin() != nullptr && !node_ptr->get_sensitive_stdin_bits().empty());

    state = BUSY;
    processed_node = node_ptr;
    samples_ptr = nullptr;
    sample_index = 0;
    execution_id = execution_id_;

    auto const  cache_it = cache.find(processed_node->get_location_id().id);
    if (cache_it != cache.end())
    {
        if (processed_node->successor(false).pointer == nullptr)
            samples_ptr = &cache_it->second.front();
        else
        {
            ASSUMPTION(processed_node->successor(true).pointer == nullptr);
            samples_ptr = &cache_it->second.back();
        }
        if (samples_ptr->empty())
            samples_ptr = nullptr;
    }

    ++statistics.start_calls;

    recorder().on_bitshare_start(processed_node, progress_recorder::START::REGULAR);
}


void  bitshare_analysis::stop()
{
    if (!is_busy())
        return;

    if (samples_ptr == nullptr)
    {
        recorder().on_bitshare_stop(progress_recorder::STOP::INSTANT);
        ++statistics.stop_calls_instant;
    }
    else if (sample_index <= samples_ptr->size())
    {
        recorder().on_bitshare_stop(progress_recorder::STOP::EARLY);
        ++statistics.stop_calls_early;
    }
    else
    {
        recorder().on_bitshare_stop(progress_recorder::STOP::REGULAR);
        ++statistics.stop_calls_regular;
    }

    processed_node->set_bitshare_performed(execution_id);

    state = READY;
}


bool  bitshare_analysis::generate_next_input(vecb&  bits_ref)
{
    TMPROF_BLOCK();

    if (!is_busy())
        return false;

    if (samples_ptr == nullptr || sample_index >= samples_ptr->size())
    {
        sample_index = std::numeric_limits<std::size_t>::max();
        stop();
        return false;
    }

    vecb const&  sample_bits = samples_ptr->at(sample_index);
    std::vector<stdin_bit_index>  bit_indices{ processed_node->get_sensitive_stdin_bits().begin(), processed_node->get_sensitive_stdin_bits().end() };
    std::sort(bit_indices.begin(), bit_indices.end());

    bits_ref = processed_node->get_best_stdin()->bits;
    for (std::size_t  i = 0; i < sample_bits.size() && i < bit_indices.size(); ++i)
        bits_ref.at(bit_indices.at(i)) = sample_bits.at(i);

    ++sample_index;

    ++statistics.generated_inputs;

    return true;
}


void  bitshare_analysis::process_execution_results(execution_trace_pointer const  trace_ptr)
{
    ASSUMPTION(is_busy());
    ASSUMPTION(trace_ptr != nullptr);

    if (!processed_node->is_direction_unexplored(false) && !processed_node->is_direction_unexplored(true))
        ++statistics.hits;
    else
        ++statistics.misses;
}


void  bitshare_analysis::bits_available_for_branching(
        branching_node* const  node_ptr,
        execution_trace_pointer const  trace,
        stdin_bits_and_types_pointer const  bits_and_types
        )
{
    TMPROF_BLOCK();

    ASSUMPTION(node_ptr != nullptr && node_ptr->was_sensitivity_performed() && !node_ptr->get_sensitive_stdin_bits().empty());
    ASSUMPTION(trace != nullptr && trace->size() > node_ptr->get_trace_index() && trace->at(node_ptr->get_trace_index()).id == node_ptr->get_location_id());
    ASSUMPTION(bits_and_types != nullptr && !bits_and_types->bits.empty());

    std::vector<stdin_bit_index>  bit_indices{ node_ptr->get_sensitive_stdin_bits().begin(), node_ptr->get_sensitive_stdin_bits().end() };
    std::sort(bit_indices.begin(), bit_indices.end());

    std::deque<vecb>&  samples = cache[node_ptr->get_location_id().id][trace->at(node_ptr->get_trace_index()).direction ? 1 : 0];
    samples.push_back({});
    for (stdin_bit_index  idx : bit_indices)
        samples.back().push_back(bits_and_types->bits.at(idx));

    statistics.num_locations = std::max(statistics.num_locations, cache.size());
    ++statistics.num_insertions;

    if (samples.size() > max_deque_size)
    {
        samples.pop_front();

        ++statistics.num_deletions;
    }
}


}
