#include <fuzzhamm/execution_trace_utils.hpp>
#include <utility/invariants.hpp>

namespace  fuzzhamm {


void  branching_classification::merge(branching_classification const&  other)
{
    // First we merge 'inner' and 'border' sets.

    for (location_id const  id : other.inner)
    {
        inner.insert(id);
        auto const  it = border.find(id);
        if (it != border.end())
            border.erase(it);
    }
    for (auto const&  id_and_dir : other.border)
    {
        auto const  it = border.find(id_and_dir.first);
        if (it == border.end())
        {
            if (inner.count(id_and_dir.first) == 0ULL)
                border.insert(id_and_dir);
        }
        else if (it->second != id_and_dir.second)
        {
            border.erase(it);
            inner.insert(id_and_dir.first);
        }
    }

    // And we copy the 'loop_*' sets.

    loop_body.insert(other.loop_body.begin(), other.loop_body.end());
    loop_head.insert(other.loop_head.begin(), other.loop_head.end());
}


void  classify_branchings(std::vector<execution_trace_record> const&  branching_records, branching_classification&  result)
{
    std::vector<location_id>  branching_stack;
    std::unordered_map<location_id, natural_32_bit>  pointers_to_branching_stack;
    branchings_hitcounts_map  branching_hit_counts;

    // We must explore the 'branching_records' backwards,
    // because of do-while loops (all loops terminate with
    // the loop-head condition, but do not have to start
    // with it).
    for (integer_32_bit  i = (integer_32_bit)branching_records.size() - 1; i >= 0; --i)
    {
        branching_coverage_info const&  coverage_info = branching_records.at(i).coverage_info;
        auto const  it = pointers_to_branching_stack.find(coverage_info.branching_id);
        if (it == pointers_to_branching_stack.end())
        {
            pointers_to_branching_stack.insert({ coverage_info.branching_id, (natural_32_bit)branching_stack.size() });
            branching_stack.push_back(coverage_info.branching_id);
        }
        else
        {
            result.loop_head.insert(coverage_info.branching_id);
            result.loop_body.insert(coverage_info.branching_id);
            for (std::size_t  end_size = it->second + 1ULL; branching_stack.size() > end_size; )
            {
                result.loop_body.insert(branching_stack.back());
                pointers_to_branching_stack.erase(branching_stack.back());
                branching_stack.pop_back();
            }
        }
        branchings_hitcounts&  hit_counts = branching_hit_counts[coverage_info.branching_id];
        if (coverage_info.covered_branch)
            ++hit_counts.num_hits_true_branch;
        else
            ++hit_counts.num_hits_false_branch;
    }

    // We must also detect 'border' and 'inner' branchings.
    for (auto const&  id_and_counts : branching_hit_counts)
    {
        branchings_hitcounts const&  hit_counts = id_and_counts.second;
        if (hit_counts.num_hits_true_branch == 0U || hit_counts.num_hits_false_branch == 0U)
            result.border.insert({ id_and_counts.first, hit_counts.num_hits_true_branch == 0U });
        else
            result.inner.insert(id_and_counts.first);
    }
}


}
