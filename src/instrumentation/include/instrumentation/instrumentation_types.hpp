#ifndef INSTRUMENTATION_INSTRUMENTATION_TYPES_HPP_INCLUDED
#   define INSTRUMENTATION_INSTRUMENTATION_TYPES_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>
#   include <iosfwd>
#   include <stdexcept>

namespace  instrumentation {

struct  terminate_exception: public std::runtime_error
{
    explicit terminate_exception(char const* const message): std::runtime_error(message) {}
};

struct  error_reached_exception: public std::runtime_error
{
    explicit error_reached_exception(char const* const message): std::runtime_error(message) {}
};

union location_id
{
    location_id(natural_32_bit const  id_, natural_32_bit const  context_hash_ = 0U)
        : id { id_ }
        , context_hash { context_hash_ }
    {}

    struct
    {
        natural_32_bit  id;
        natural_32_bit  context_hash;
    };

    natural_64_bit  uid;
};

inline bool operator==(location_id const l, location_id const r) { return l.uid == r.uid; }
inline bool operator!=(location_id const l, location_id const r) { return l.uid != r.uid; }
inline bool operator<(location_id const l, location_id const r) { return l.id < r.id || (l.id == r.id && l.context_hash < r.context_hash); }
inline location_id  invalid_location_id() { return {0U}; }
std::ostream&  operator<<(std::ostream&  ostr, location_id  id);


using coverage_distance_type = float_64_bit;


struct  branching_coverage_info
{
    explicit branching_coverage_info(location_id const  id);

    location_id  branching_id;
    bool  covered_branch;
    coverage_distance_type  distance_to_uncovered_branch; // Is always positive!
};


bool  is_same_branching(branching_coverage_info const&  l, branching_coverage_info const&  r);


}


template<> struct std::hash<instrumentation::location_id> {
    std::size_t operator()(instrumentation::location_id const id) const noexcept { return id.uid; }
};


#endif
