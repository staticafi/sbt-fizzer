#include <fuzzhamm/execution_trace_utils.hpp>

namespace  fuzzhamm {


void  compute_histograms_of_branchings(
        std::vector<execution_trace_record> const&  branching_records,
        location_id const  loc_id,
        std::vector<std::pair<natural_32_bit, std::unordered_map<location_id, std::pair<natural_32_bit, natural_32_bit> > > >&  histograms
        )
{
    std::unordered_map<location_id, std::pair<natural_32_bit, natural_32_bit> >  hist;
    for (natural_32_bit  i = 0U, n = (natural_32_bit)branching_records.size(); i != n; ++i)
    {
        execution_trace_record const&  rec = branching_records.at(i);
        auto&  counters = hist.insert({ rec.coverage_info.branching_id, { 0U, 0U } }).first->second;
        if (rec.coverage_info.covered_branch)
            ++counters.first;
        else
            ++counters.second;
        if (rec.coverage_info.branching_id == loc_id)
            histograms.push_back({ i, hist });
    }
}


}
