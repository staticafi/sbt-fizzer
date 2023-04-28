#ifndef FUZZING_EXECUTION_TRACE_HPP_INCLUDED
#   define FUZZING_EXECUTION_TRACE_HPP_INCLUDED

#   include <instrumentation/instrumentation_types.hpp>
#   include <vector>
#   include <memory>
#   include <limits>

using namespace  instrumentation;

namespace  fuzzing {


using  execution_trace = std::vector<branching_coverage_info>;
using  execution_trace_pointer = std::shared_ptr<execution_trace>;

using  br_instr_execution_trace = std::vector<br_instr_coverage_info>;
using  br_instr_execution_trace_pointer = std::shared_ptr<br_instr_execution_trace>;

using  trace_index_type = natural_32_bit;
static natural_32_bit constexpr  invalid_trace_index{ std::numeric_limits<trace_index_type>::max() };

using  branching_location_and_direction = std::pair<location_id, bool>;
using  execution_path = std::vector<branching_location_and_direction>;

bool  operator<(execution_path const&  left, execution_path const&  right);
bool  operator==(execution_path const&  left, execution_path const&  right);

inline bool  operator!=(execution_path const&  left, execution_path const&  right) { return !(left == right); }


}

#endif
