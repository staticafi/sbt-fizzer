#include <fuzzhamm/execution_trace_utils.hpp>

namespace  fuzzhamm {


void  compute_escape_sensitive_bits_for_branchings(
        execution_trace_const_ptr const  trace,
        std::vector<std::unordered_set<natural_16_bit> >&  result
        )
{
    result.resize(trace->branching_records.size());
    for (natural_32_bit  i = 1U, n = (natural_32_bit)trace->branching_records.size(); i < n; ++i)
    {
        result.at(i).insert(result.at(i - 1U).begin(), result.at(i - 1U).end());
        result.at(i).insert(trace->branching_records.at(i - 1U).sensitive_stdin_bits.begin(),
                            trace->branching_records.at(i - 1U).sensitive_stdin_bits.end());
        result.at(i).insert(trace->branching_records.at(i - 1U).diverged_stdin_bits.begin(),
                            trace->branching_records.at(i - 1U).diverged_stdin_bits.end());
    }
}


void  split_branching_sensitive_bits_to_pure_and_escape(
            std::unordered_set<natural_16_bit> const&  branching_all_sensitive_bits,
            std::unordered_set<natural_16_bit> const&  branching_escape_sensitive_bits,
            std::unordered_set<natural_16_bit>&  pure_sensitive_bits,
            std::unordered_set<natural_16_bit>* const  escape_sensitive_bits
            )
{
    for (natural_16_bit const  bit_index : branching_all_sensitive_bits)
        if (branching_escape_sensitive_bits.count(bit_index) == 0ULL)
            pure_sensitive_bits.insert(bit_index);
        else if (escape_sensitive_bits != nullptr)
            escape_sensitive_bits->insert(bit_index);
}


}
