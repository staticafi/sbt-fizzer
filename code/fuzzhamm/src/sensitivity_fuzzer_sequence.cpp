#include <fuzzhamm/sensitivity_fuzzer_sequence.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>

namespace  fuzzhamm {


sensitivity_fuzzer_sequence::sensitivity_fuzzer_sequence(
        execution_trace_ptr const  the_trace,
        std::size_t const  max_size_,
        sensitivity_fuzzer_base_ptr const  parent)
    : sensitivity_fuzzer_base(the_trace, parent)
    , fuzzer_chain()
    , active_fuzzer_index(0UL)
    , max_size(max_size_)
{}


bool  sensitivity_fuzzer_sequence::push_back(sensitivity_fuzzer_base_ptr const  fuzzer)
{
    ASSUMPTION(fuzzer != nullptr);
    if (fuzzer_chain.size() < max_size)
    {
        fuzzer_chain.push_back(fuzzer);
        return true;
    }
    return false;
}


void  sensitivity_fuzzer_sequence::update(execution_trace_const_ptr const  sample_trace, std::size_t const  diverging_branch_index)
{
    if (active_fuzzer_index < fuzzer_chain.size())
        fuzzer_chain.at(active_fuzzer_index)->on_sample(sample_trace, diverging_branch_index);
}


void  sensitivity_fuzzer_sequence::mutate(vecb&  input_stdin)
{
    if (active_fuzzer_index < fuzzer_chain.size())
        fuzzer_chain.at(active_fuzzer_index)->compute_input(input_stdin);
}


bool  sensitivity_fuzzer_sequence::done()
{
    move_in_chain();
    return active_fuzzer_index == fuzzer_chain.size();
}


void  sensitivity_fuzzer_sequence::move_in_chain()
{
    while (active_fuzzer_index < fuzzer_chain.size() && fuzzer_chain.at(active_fuzzer_index)->done())
        ++active_fuzzer_index;
}


}
