#include <fuzzing/bitshare_analysis.hpp>
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

void  bitshare_analysis::start(branching_node*  node_ptr)
{
    ASSUMPTION(is_ready());
    ASSUMPTION(node_ptr != nullptr && node_ptr->best_stdin != nullptr && !node_ptr->sensitive_stdin_bits.empty());

    state = BUSY;
    processed_node = node_ptr;
    samples_ptr = nullptr;
    sample_index = 0;

    auto const  cache_it = cache.find(processed_node->id.id);
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
}


void  bitshare_analysis::stop()
{
    if (!is_busy())
        return;

    if (samples_ptr == nullptr)
        ++statistics.stop_calls_instant;
    else if (sample_index < samples_ptr->size())
        ++statistics.stop_calls_early;
    else
        ++statistics.stop_calls_regular;

    processed_node->bitshare_performed = true;

    state = READY;
    processed_node = nullptr;
    samples_ptr = nullptr;
    sample_index = 0;
}


bool  bitshare_analysis::generate_next_input(vecb&  bits_ref)
{
    TMPROF_BLOCK();

    if (!is_busy())
        return false;

    if (samples_ptr == nullptr || sample_index >= samples_ptr->size())
    {
        stop();
        return false;
    }

    vecb const&  sample_bits = samples_ptr->at(sample_index);
    std::vector<stdin_bit_index>  bit_indices{ processed_node->sensitive_stdin_bits.begin(), processed_node->sensitive_stdin_bits.end() };
    std::sort(bit_indices.begin(), bit_indices.end());

    bits_ref = *processed_node->best_stdin;
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

    if (processed_node->is_direction_explored(false) && processed_node->is_direction_explored(true))
        ++statistics.hits;
    else
        ++statistics.misses;
}


void  bitshare_analysis::bits_available_for_branching(
        branching_node* const  node_ptr,
        execution_trace_pointer const  trace,
        stdin_bits_pointer const  stdin_bits
        )
{
    TMPROF_BLOCK();

    ASSUMPTION(node_ptr != nullptr && node_ptr->sensitivity_performed && !node_ptr->sensitive_stdin_bits.empty());
    ASSUMPTION(trace != nullptr && trace->size() > node_ptr->trace_index && trace->at(node_ptr->trace_index).id == node_ptr->id);
    ASSUMPTION(stdin_bits != nullptr && !stdin_bits->empty());

    std::vector<stdin_bit_index>  bit_indices{ node_ptr->sensitive_stdin_bits.begin(), node_ptr->sensitive_stdin_bits.end() };
    std::sort(bit_indices.begin(), bit_indices.end());

    std::deque<vecb>&  samples = cache[node_ptr->id.id][trace->at(node_ptr->trace_index).direction ? 1 : 0];
    samples.push_back({});
    for (stdin_bit_index  idx : bit_indices)
        samples.back().push_back(stdin_bits->at(idx));

    statistics.num_locations = std::max(statistics.num_locations, cache.size());
    ++statistics.num_insertions;

    if (samples.size() > max_deque_size)
    {
        samples.pop_front();

        ++statistics.num_deletions;
    }
}


}