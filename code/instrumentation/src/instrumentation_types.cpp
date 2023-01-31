#include <instrumentation/instrumentation_types.hpp>
#include <ostream>

namespace  instrumentation {


branching_coverage_info::branching_coverage_info(location_id const  id)
    : branching_id(id)
    , covered_branch{}
    , distance_to_uncovered_branch{}
{}


bool  is_same_branching(branching_coverage_info const&  l, branching_coverage_info const&  r)
{
    return l.branching_id == r.branching_id && l.covered_branch == r.covered_branch;
}

std::ostream&  operator<<(std::ostream&  ostr, location_id const  id)
{
    ostr << id.id << '@' << id.context_hash;
    return ostr;
}


}
