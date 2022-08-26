#include <fuzzhamm/sensitivity_fuzzer_progress_check.hpp>
#include <fuzzhamm/sensitivity_fuzzer_sequence.hpp>
#include <fuzzhamm/sensitivity_fuzzer_similar_trace_search.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>

namespace  fuzzhamm {


sensitivity_fuzzer_progress_check::sensitivity_fuzzer_progress_check(
        execution_trace_ptr const  the_trace,
        execution_trace_ptr const  original_trace_,
        sensitivity_fuzzer_base_ptr const  parent,
        bool const  similarity_only_for_uncovered_branchings_
        )
    : sensitivity_fuzzer_base(the_trace, parent)
    , original_trace(original_trace_)
    , similarity_only_for_uncovered_branchings(similarity_only_for_uncovered_branchings_)
{
    ASSUMPTION(original_trace != nullptr && parent != nullptr && std::dynamic_pointer_cast<sensitivity_fuzzer_sequence>(parent) != nullptr);
}


bool  sensitivity_fuzzer_progress_check::done()
{
    bool  sensitivity_changed = false;
    if (trace() == get_original_trace())
        sensitivity_changed = trace()->sensitive_stdin_bits.size() < trace()->input_stdin.size();
    else
    {
        {
            std::size_t const  old_size = get_original_trace()->sensitive_stdin_bits.size();
            get_original_trace()->sensitive_stdin_bits.insert(trace()->sensitive_stdin_bits.begin(), trace()->sensitive_stdin_bits.end());
            if (old_size != get_original_trace()->sensitive_stdin_bits.size())
                sensitivity_changed = true;
        }
        for (std::size_t i = 0, n = trace()->branching_records.size(); i < n; ++i)
        {
            std::size_t const  old_size = get_original_trace()->branching_records.at(i).sensitive_stdin_bits.size();
            get_original_trace()->branching_records.at(i).sensitive_stdin_bits.insert(
                    trace()->branching_records.at(i).sensitive_stdin_bits.begin(),
                    trace()->branching_records.at(i).sensitive_stdin_bits.end()
                    );
            if (old_size != get_original_trace()->branching_records.at(i).sensitive_stdin_bits.size())
                sensitivity_changed = true;
        }
    }
    if (sensitivity_changed)
    {
        sensitivity_fuzzer_sequence_ptr const  fuzzer_sequence_ptr = std::dynamic_pointer_cast<sensitivity_fuzzer_sequence>(parent());
        fuzzer_sequence_ptr->push_back(
                std::make_shared<sensitivity_fuzzer_similar_trace_search>(get_original_trace(), fuzzer_sequence_ptr, similarity_only_for_uncovered_branchings)
                );
    }
    return true;
}


}
