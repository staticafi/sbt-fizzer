#include <fuzzhamm/sensitivity_fuzzer_hamming.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>

namespace  fuzzhamm {


sensitivity_fuzzer_hamming::sensitivity_fuzzer_hamming(
        execution_trace_weak_ptr const  the_trace,
        natural_16_bit const  num_bit_indices,
        sensitivity_fuzzer_base_weak_ptr  parent_ptr
        )
    : sensitivity_fuzzer_base(the_trace, parent_ptr)
    , bit_indices()
    , finished(false)
{
    make_first_combination(bit_indices, num_bit_indices);
}


void  sensitivity_fuzzer_hamming::update(execution_trace_const_ptr  sample_trace, std::size_t  diverging_branch_index)
{
    update_per_branching(sample_trace, diverging_branch_index, bit_indices);
}


void  sensitivity_fuzzer_hamming::mutate(vecb&  input_stdin)
{
    for (natural_16_bit  bit_index : bit_indices)
        input_stdin.at(bit_index) = !input_stdin.at(bit_index);
}


bool  sensitivity_fuzzer_hamming::done()
{
    finished = finished || !make_next_combination(bit_indices, (natural_16_bit)trace()->input_stdin.size());
    return finished;
}


}
