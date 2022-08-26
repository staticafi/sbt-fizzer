#include <instrumentation/instrumentation_types.hpp>

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


}
