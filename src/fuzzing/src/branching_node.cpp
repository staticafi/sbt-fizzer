#include <fuzzing/branching_node.hpp>
#include <utility/assumptions.hpp>

namespace  fuzzing {

int fuzzing::branching_node::get_depth() const
{
    int depth = 0;
    for ( branching_node const* node = this; node != nullptr; node = node->predecessor )
        ++depth;
    return depth;
}

branching_node::guid_type  branching_node::get_fresh_guid__()
{
    static guid_type  fresh_guid_counter{ 0U };
    guid_type const  result{ ++fresh_guid_counter };
    ASSUMPTION(result != 0);
    return result;
}


}
