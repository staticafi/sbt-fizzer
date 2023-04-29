#include <instrumentation/instrumentation_types.hpp>
#include <ostream>

namespace  instrumentation {


branching_coverage_info::branching_coverage_info(location_id const  id_)
    : id{id_}
    , direction{}
    , value{}
    , idx_to_br_instr{}
{}

size_t branching_coverage_info::flattened_size() {
    return sizeof(id) + sizeof(direction) + sizeof(value) + sizeof(idx_to_br_instr);
}

br_instr_coverage_info::br_instr_coverage_info(location_id const  id)
    : br_instr_id(id)
    , covered_branch{}
{}

size_t br_instr_coverage_info::flattened_size() {
    return sizeof(br_instr_id) + sizeof(covered_branch);
}



bool  is_same_branching(branching_coverage_info const&  l, branching_coverage_info const&  r)
{
    return l.id == r.id && l.direction == r.direction;
}

std::ostream&  operator<<(std::ostream&  ostr, location_id const  id)
{
    ostr << id.id << '!' << id.context_hash;
    return ostr;
}


}
