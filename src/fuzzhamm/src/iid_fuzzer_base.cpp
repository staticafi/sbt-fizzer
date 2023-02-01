#include <fuzzhamm/iid_fuzzer_base.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>

namespace  fuzzhamm {


iid_fuzzer_base::iid_fuzzer_base(location_id const id)
    : loc_id_(id)
    , generator(0U)
    , num_inputs_generated(0U)
{
}


void  iid_fuzzer_base::on_new_trace(execution_trace_ptr const  trace, std::unordered_set<natural_32_bit> const&  target_branching_indices)
{
    new_trace(trace, target_branching_indices);
}


void  iid_fuzzer_base::on_sample(execution_trace_ptr const  sample_trace)
{
    update(sample_trace);
}


void  iid_fuzzer_base::compute_input(vecb&  input_stdin)
{
    input_stdin.clear();
    generate(input_stdin);
    ++num_inputs_generated;
}


}
