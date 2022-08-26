#include <fuzzhamm/branching_fuzzer_sequence.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>

namespace  fuzzhamm {


branching_fuzzer_sequence::branching_fuzzer_sequence(std::size_t const  max_size_)
    : fuzzer_chain()
    , active_fuzzer_index(0UL)
    , max_size(max_size_)
{}


bool  branching_fuzzer_sequence::push_back(branching_fuzzer_base_ptr const  fuzzer)
{
    ASSUMPTION(fuzzer != nullptr);
    if (fuzzer_chain.size() < max_size)
    {
        fuzzer_chain.push_back(fuzzer);
        return true;
    }
    return false;
}


void  branching_fuzzer_sequence::on_sample(vecb const&  input_stdin, coverage_distance_type const  distance, bool const  diverged)
{
    if (active_fuzzer_index < fuzzer_chain.size())
        fuzzer_chain.at(active_fuzzer_index)->on_sample(input_stdin, distance, diverged);
}


void  branching_fuzzer_sequence::compute_input(vecb&  input_stdin)
{
    if (active_fuzzer_index < fuzzer_chain.size())
        fuzzer_chain.at(active_fuzzer_index)->compute_input(input_stdin);
}


bool  branching_fuzzer_sequence::done()
{
    move_in_chain();
    return active_fuzzer_index == fuzzer_chain.size();
}


void  branching_fuzzer_sequence::move_in_chain()
{
    while (active_fuzzer_index < fuzzer_chain.size() && fuzzer_chain.at(active_fuzzer_index)->done())
        ++active_fuzzer_index;
}


}
