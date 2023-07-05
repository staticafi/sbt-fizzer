#include <utility/basic_numeric_types.hpp>
#include <instrumentation/instrumentation_types.hpp>
#include <instrumentation/fuzz_target.hpp>
#include <utility/invariants.hpp>
#include <cmath>

using namespace instrumentation;

extern "C" {

void __sbt_fizzer_process_condition(location_id id, bool branch, branching_function_value_type value, bool xor_like_branching_function) {
    sbt_fizzer_target->process_condition(id, branch, value, xor_like_branching_function);
}

void __sbt_fizzer_process_br_instr(location_id id, bool branch) {
    sbt_fizzer_target->process_br_instr(id, branch);
}

void __sbt_fizzer_process_call_begin(natural_32_bit const  id) {
    sbt_fizzer_target->process_call_begin(id);
}

void __sbt_fizzer_process_call_end(natural_32_bit const  id) {
    sbt_fizzer_target->process_call_end(id);
}

}