#include <fuzzing/branching_node.hpp>
#include <utility/assumptions.hpp>

namespace  fuzzing {


branching_node::guid_type  branching_node::get_fresh_guid__()
{
    static guid_type  fresh_guid_counter{ 0U };
    guid_type const  result{ ++fresh_guid_counter };
    ASSUMPTION(result != 0);
    return result;
}


}
