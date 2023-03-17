#include <fuzzing/execution_trace.hpp>
#include <utility/assumptions.hpp>

namespace  fuzzing {


bool  is_same_branching(branching_coverage_info const&  l, branching_coverage_info const&  r)
{
    return l.id == r.id && l.direction == r.direction;
}


bool  operator<(execution_path const&  left, execution_path const&  right)
{
    return left.size() < right.size();
}


bool  operator==(execution_path const&  left, execution_path const&  right)
{
    if (left.size() != right.size())
        return false;
    for (std::size_t  i = 0; i != left.size(); ++i)
        if (left.at(i) != right.at(i))
            return false;
    return true;
}


}
