#include <fuzzhamm/sensitivity_fuzzer_base.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>

namespace  fuzzhamm {


sensitivity_fuzzer_base::sensitivity_fuzzer_base(execution_trace_weak_ptr const  the_trace, sensitivity_fuzzer_base_weak_ptr  parent_ptr)
    : parent_(parent_ptr)
    , trace_(the_trace)
    , generator(0U)
    , num_inputs_generated(0U)
{}


void  sensitivity_fuzzer_base::on_sample(execution_trace_const_ptr  sample_trace, std::size_t  diverging_branch_index)
{
    update(sample_trace, diverging_branch_index);
}


void  sensitivity_fuzzer_base::compute_input(vecb&  input_stdin)
{
    input_stdin = trace()->input_stdin;
    mutate(input_stdin);
    ++num_inputs_generated;
}


bool  sensitivity_fuzzer_base::done()
{
    return false;
}


void  sensitivity_fuzzer_base::update_per_branching(
            execution_trace_const_ptr  sample_trace,
            std::size_t  diverging_branch_index,
            std::vector<natural_16_bit> const&  bit_indices
            )
{
    for (std::size_t i = 0, n = std::min(diverging_branch_index, trace()->branching_records.size() - 1UL); i <= n; ++i)
    {
        execution_trace_record const&  cr = sample_trace->branching_records.at(i);
        execution_trace_record&  pr = trace()->branching_records.at(i);
        if (i == diverging_branch_index || cr.coverage_info.distance_to_uncovered_branch != pr.coverage_info.distance_to_uncovered_branch)
            for (natural_16_bit  bit_index : bit_indices)
            {
                trace()->sensitive_stdin_bits.insert(bit_index);
                pr.sensitive_stdin_bits.insert(bit_index);
            }
    }
}


}
