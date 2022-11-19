#ifndef INSTRUMENTATION_INSTRUMENTATION_TYPES_HPP_INCLUDED
#   define INSTRUMENTATION_INSTRUMENTATION_TYPES_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>

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

using  location_id = natural_32_bit;
constexpr inline location_id  invalid_location_id() { return 0U; }


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

#endif
