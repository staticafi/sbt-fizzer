#ifndef INSTRUMENTATION_INSTRUMENTATION_TYPES_HPP_INCLUDED
#   define INSTRUMENTATION_INSTRUMENTATION_TYPES_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>
#   include <functional>
#   include <iosfwd>

namespace  instrumentation {


union location_id
{
    using  id_type = natural_32_bit;
    using  context_type = natural_32_bit;

    location_id(id_type const  id_, context_type const  context_hash_ = 0U)
        : id { id_ }
        , context_hash { context_hash_ }
    {}

    struct
    {
        id_type  id;
        context_type  context_hash;
    };

    natural_64_bit  uid;
};

inline bool operator==(location_id const l, location_id const r) { return l.uid == r.uid; }
inline bool operator!=(location_id const l, location_id const r) { return l.uid != r.uid; }
inline bool operator<(location_id const l, location_id const r) { return l.id < r.id || (l.id == r.id && l.context_hash < r.context_hash); }
inline location_id  invalid_location_id() { return {0U}; }
std::ostream&  operator<<(std::ostream&  ostr, location_id  id);


using branching_function_value_type = float_64_bit;

struct  branching_coverage_info
{
    explicit branching_coverage_info(location_id const  id_);

    location_id  id;
    bool  direction;
    branching_function_value_type  value;
    natural_32_bit  idx_to_br_instr;
};


struct  br_instr_coverage_info
{
    explicit br_instr_coverage_info(location_id const  id);

    location_id  br_instr_id;
    bool  covered_branch;
};


bool  is_same_branching(branching_coverage_info const&  l, branching_coverage_info const&  r);


}


template<> struct std::hash<instrumentation::location_id> {
    std::size_t operator()(instrumentation::location_id const id) const noexcept { return id.uid; }
};


#endif
