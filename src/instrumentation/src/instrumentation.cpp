#include <utility/basic_numeric_types.hpp>
#include <instrumentation/instrumentation_types.hpp>
#include <instrumentation/exceptions.hpp>
#include <iomodels/instrumentation_callbacks.hpp>
#include <utility/invariants.hpp>
#include <cmath>

namespace instrumentation {

static void sbt_fizzer_process_condition(location_id id, bool branch, branching_function_value_type value) {
    branching_coverage_info info(id);
    info.direction = branch;

    if (std::isnan(value)) {
        value = std::numeric_limits<branching_function_value_type>::max();
    }
    info.value = value;
        
    iomodels::on_branching(info);
}

static void sbt_fizzer_process_br_instr(location_id id, bool branch) {
    br_instr_coverage_info info(id);
    info.covered_branch = branch;
    iomodels::on_br_instr(info);
}

static void sbt_fizzer_terminate() {
    throw terminate_exception("");
}

static void sbt_fizzer_reach_error() {
    throw error_reached_exception("Error reached");
}

static void sbt_fizzer_process_call_begin(natural_32_bit const  id) {
    iomodels::on_call_begin(id);
}

static void sbt_fizzer_process_call_end(natural_32_bit const  id) {
    iomodels::on_call_end(id);
}

extern "C" {

void __sbt_fizzer_process_condition(location_id id, bool branch, branching_function_value_type value) {
    sbt_fizzer_process_condition(id, branch, value);
}

void __sbt_fizzer_process_br_instr(location_id id, bool branch) {
    sbt_fizzer_process_br_instr(id, branch);
}

void __sbt_fizzer_process_call_begin(natural_32_bit const  id) {
    sbt_fizzer_process_call_begin(id);
}

void __sbt_fizzer_process_call_end(natural_32_bit const  id) {
    sbt_fizzer_process_call_end(id);
}

void __sbt_fizzer_terminate() {
    sbt_fizzer_terminate();
}

void __sbt_fizzer_reach_error() {
    sbt_fizzer_reach_error();
}

}

}