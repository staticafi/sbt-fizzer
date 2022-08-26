#include <fuzzhamm/sensitivity_fuzzer_similar_trace_search.hpp>
#include <fuzzhamm/sensitivity_fuzzer_sequence.hpp>
#include <fuzzhamm/sensitivity_fuzzer_hamming.hpp>
#include <fuzzhamm/sensitivity_fuzzer_progress_check.hpp>
#include <fuzzhamm/execution_trace_utils.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>

namespace  fuzzhamm {


sensitivity_fuzzer_similar_trace_search::sensitivity_fuzzer_similar_trace_search(
        execution_trace_ptr const  the_trace,
        sensitivity_fuzzer_base_ptr const  parent,
        bool const  consider_only_uncovered_branchings_
        )
    : sensitivity_fuzzer_base(the_trace, parent)
    , sensitive_stdin_bits()
    , counter(0U)
    , max_counter(10U)
    , similar_trace(nullptr)
    , consider_only_uncovered_branchings(consider_only_uncovered_branchings_)
{
    ASSUMPTION(parent != nullptr && std::dynamic_pointer_cast<sensitivity_fuzzer_sequence>(parent) != nullptr);

    std::vector<std::unordered_set<natural_16_bit> >  escape_stdin_bits;
    compute_escape_sensitive_bits_for_branchings(trace(), escape_stdin_bits);

    if (consider_only_uncovered_branchings)
        for (auto const&  loc_and_indices : trace()->uncovered_branchings)
            for (auto  idx : loc_and_indices.second)
            {
                execution_trace_record&  rec = trace()->branching_records.at(idx);
                sensitive_stdin_bits.insert(rec.sensitive_stdin_bits.begin(), rec.sensitive_stdin_bits.end());
            }
    else
        for (natural_32_bit  i = 0U, n = (natural_32_bit)trace()->branching_records.size(); i < n; ++i)
        {
            execution_trace_record&  rec = trace()->branching_records.at(i);
            sensitive_stdin_bits.insert(rec.sensitive_stdin_bits.begin(), rec.sensitive_stdin_bits.end());
        }
}


void  sensitivity_fuzzer_similar_trace_search::update(execution_trace_const_ptr const  sample_trace, std::size_t const  diverging_branch_index)
{
    if (similar_trace == nullptr
            && diverging_branch_index == sample_trace->branching_records.size()
            && diverging_branch_index == trace()->branching_records.size()
            )
    {
        INVARIANT(trace()->hash_code == sample_trace->hash_code); // Ensure the 'sample_trace' we take here will NOT be added to fuzzed 'traces'.
        similar_trace = std::const_pointer_cast<execution_trace>(sample_trace);

        sensitivity_fuzzer_sequence_ptr const  fuzzer_sequence_ptr = std::dynamic_pointer_cast<sensitivity_fuzzer_sequence>(parent());
        fuzzer_sequence_ptr->push_back(
                std::make_shared<sensitivity_fuzzer_hamming>(get_similar_trace(), 1U, fuzzer_sequence_ptr)
                );
        fuzzer_sequence_ptr->push_back(
                std::make_shared<sensitivity_fuzzer_progress_check>(get_similar_trace(), trace(), fuzzer_sequence_ptr, consider_only_uncovered_branchings)
                );
    }
}


void  sensitivity_fuzzer_similar_trace_search::mutate(vecb&  input_stdin)
{
    if (sensitive_stdin_bits.size() > 1UL)
        for (auto  it = sensitive_stdin_bits.begin(); it != sensitive_stdin_bits.end(); ++it)
            input_stdin.at(*it) = (natural_8_bit)get_random_natural_32_bit_in_range(0U, 255U, generator_ref()) < 128U;

    ++counter;
    if (counter > max_counter)
        counter = 0U;
}


bool  sensitivity_fuzzer_similar_trace_search::done()
{
    return sensitive_stdin_bits.size() < 2UL || get_similar_trace() != nullptr;
}


}
