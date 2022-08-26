#include <fuzzhamm/execution_trace_utils.hpp>

namespace  fuzzhamm {


void  compute_indices_of_branchings(std::vector<execution_trace_record> const&  branching_records, branchings_indices_map&  result)
{
    for (natural_32_bit  i = 0U, n = (natural_32_bit)branching_records.size(); i < n; ++i)
        result[branching_records.at(i).coverage_info.branching_id].push_back(i);
}


void  compute_indices_of_location_id(std::vector<execution_trace_record> const&  branching_records, location_id const  id, std::vector<natural_32_bit>&  result)
{
    for (natural_32_bit  i = 0U, n = (natural_32_bit)branching_records.size(); i < n; ++i)
        if (id == branching_records.at(i).coverage_info.branching_id)
            result.push_back(i);
}


natural_32_bit  index_of_branching_record_with_min_coverage_distance(std::vector<execution_trace_record> const&  branching_records, location_id const  id)
{
    natural_32_bit  best_i;
    execution_trace_record const*  best_rec_ptr = nullptr;
    for (natural_32_bit  i = 0U, n = (natural_32_bit)branching_records.size(); i < n; ++i)
    {
        execution_trace_record const&  rec = branching_records.at(i);
        if (rec.coverage_info.branching_id == id && (
                best_rec_ptr == nullptr ||
                rec.coverage_info.distance_to_uncovered_branch < best_rec_ptr->coverage_info.distance_to_uncovered_branch))
        {
            best_i = i;
            best_rec_ptr = &rec;
        }
    }
    return best_rec_ptr == nullptr ? (natural_32_bit)branching_records.size() : best_i;
}


void  compute_hitcounts_of_branchings(std::vector<execution_trace_record> const&  branching_records, branchings_hitcounts_map&  result)
{
    for (natural_32_bit  i = 0U, n = (natural_32_bit)branching_records.size(); i < n; ++i)
    {
        branching_coverage_info const&  coverage_info = branching_records.at(i).coverage_info;
        branchings_hitcounts&  hit_counts = result[coverage_info.branching_id];

        if (coverage_info.covered_branch)
            ++hit_counts.num_hits_true_branch;
        else
            ++hit_counts.num_hits_false_branch;
    }
}


std::size_t  compute_diverging_branch_index(
        std::vector<execution_trace_record> const&  reference_branching_records,
        std::vector<execution_trace_record> const&  checked_branching_records,
        std::size_t  end_index
        )
{
    std::size_t  diverging_branch_index = 0UL;
    for (std::size_t n = std::min(std::min(reference_branching_records.size(), checked_branching_records.size()), end_index);
            diverging_branch_index < n
                && is_same_branching(reference_branching_records.at(diverging_branch_index).coverage_info,
                                     checked_branching_records.at(diverging_branch_index).coverage_info);
            ++diverging_branch_index
            );
    return diverging_branch_index;
}


}
