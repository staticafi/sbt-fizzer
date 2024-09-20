#ifndef FUZZING_INSTRUMENTATION_TYPES_HPP_INCLUDED
#   define FUZZING_INSTRUMENTATION_TYPES_HPP_INCLUDED

#   include <instrumentation/instrumentation_types.hpp>

namespace  fuzzing {


using  location_id = instrumentation::location_id;
using  branching_coverage_info = instrumentation::branching_coverage_info;
using  br_instr_coverage_info = instrumentation::br_instr_coverage_info;
using  branching_function_value_type = instrumentation::branching_function_value_type;
using  BRANCHING_PREDICATE = instrumentation::BRANCHING_PREDICATE;
using  type_of_input_bits = instrumentation::type_of_input_bits;

using  instrumentation::invalid_location_id;


}

#endif
