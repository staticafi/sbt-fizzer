#include <utility/basic_numeric_types.hpp>
#include <instrumentation/instrumentation_types.hpp>
#include <instrumentation/fuzz_target.hpp>
#include <utility/invariants.hpp>
#include <cmath>

using namespace instrumentation;

extern "C" {

void __sbt_fizzer_process_condition(
        location_id::id_type const  id,
        bool const  direction,
        branching_function_value_type const   value,
        bool const  xor_like_branching_function,
        natural_8_bit const  predicate
        ) {
    sbt_fizzer_target->process_condition(id, direction, value, xor_like_branching_function, predicate);
}

void __sbt_fizzer_process_br_instr(location_id::id_type const  id, bool const  direction) {
    sbt_fizzer_target->process_br_instr(id, direction);
}

void __sbt_fizzer_process_call_begin(location_id::id_type const  id) {
    sbt_fizzer_target->process_call_begin(id);
}

void __sbt_fizzer_process_call_end(location_id::id_type const  id) {
    sbt_fizzer_target->process_call_end(id);
}

}