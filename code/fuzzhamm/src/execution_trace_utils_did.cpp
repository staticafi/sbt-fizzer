#include <fuzzhamm/execution_trace_utils.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>

namespace  fuzzhamm {


void  compute_colliding_stdin_bits(std::vector<execution_trace_record>&  branching_records)
{
    std::unordered_set<natural_16_bit>  colliding_stdin_bits;
    for (execution_trace_record&  rec : branching_records)
        for (natural_16_bit  idx : rec.sensitive_stdin_bits)
            if (colliding_stdin_bits.count(idx) != 0ULL)
                rec.colliding_stdin_bits.insert(idx);
            else
                colliding_stdin_bits.insert(idx);
}


did_branching_selection_penalty::did_branching_selection_penalty()
    : num_sensitive_bits(std::numeric_limits<natural_32_bit>::max())
    , num_diverged_bits(std::numeric_limits<natural_32_bit>::max())
    , num_colliding_bits(std::numeric_limits<natural_32_bit>::max())
{}


did_branching_selection_penalty::did_branching_selection_penalty(execution_trace_record const&  rec)
    : num_sensitive_bits((natural_32_bit)rec.sensitive_stdin_bits.size())
    , num_diverged_bits((natural_32_bit)rec.sensitive_stdin_bits.size())
    , num_colliding_bits((natural_32_bit)rec.sensitive_stdin_bits.size())
{}


bool  operator<(did_branching_selection_penalty const&  left, did_branching_selection_penalty const&  right)
{
    auto const  penalty = [](did_branching_selection_penalty const&  props) -> natural_32_bit {
        return props.num_sensitive_bits + 5U * props.num_colliding_bits + 10U * props.num_diverged_bits;
    };
    return penalty(left) < penalty(right);
}


}
