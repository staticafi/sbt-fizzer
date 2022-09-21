#include <fuzzhamm/execution_trace_utils.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>

namespace  fuzzhamm {


void  compute_diverged_and_colliding_stdin_bits(std::vector<execution_trace_record>&  branching_records)
{
    std::unordered_map<natural_16_bit, std::unordered_set<natural_32_bit> >  from_bit_indices_to_record_indices;
    std::unordered_map<natural_32_bit, std::unordered_map<natural_16_bit, std::unordered_set<natural_16_bit> > >  from_record_and_byte_indices_to_bit_indices;
    for (natural_32_bit  i = 0U, n = (natural_32_bit)branching_records.size(); i != n; ++i)
    {
        execution_trace_record&  rec = branching_records.at(i);

        std::unordered_set<natural_32_bit>  diverging_record_indices;
        for (natural_16_bit  idx : rec.sensitive_stdin_bits)
        {
            auto const  it = from_bit_indices_to_record_indices.find(idx);
            if (it != from_bit_indices_to_record_indices.end())
            {
                diverging_record_indices.insert(it->second.begin(), it->second.end());
                rec.colliding_stdin_bits.insert(idx);
            }
            from_bit_indices_to_record_indices[idx].insert(i);
            from_record_and_byte_indices_to_bit_indices[i][idx >> 3].insert(idx);
        }
        if (!diverging_record_indices.empty())
        {
            auto const&  my_sensitive_bytes = from_record_and_byte_indices_to_bit_indices.at(i);
            for (natural_32_bit  rec_idx : diverging_record_indices)
            {
                auto const&  from_byte_indices_to_bit_indices = from_record_and_byte_indices_to_bit_indices[rec_idx];
                for (auto const&  byte_and_bit_indices : my_sensitive_bytes)
                {
                    auto const  it = from_byte_indices_to_bit_indices.find(byte_and_bit_indices.first);
                    if (it != from_byte_indices_to_bit_indices.end())
                        rec.diverged_stdin_bits.insert(it->second.begin(), it->second.end());
                }
            }
        }
        for (natural_16_bit  idx : rec.sensitive_stdin_bits)
            rec.diverged_stdin_bits.erase(idx);
    }
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
