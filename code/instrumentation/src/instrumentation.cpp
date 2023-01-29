#include <utility/basic_numeric_types.hpp>
#include <instrumentation/instrumentation_types.hpp>
#include <iomodels/instrumentation_callbacks.hpp>
#include <utility/invariants.hpp>
#include <cmath>

namespace instrumentation {

static void sbt_fizzer_process_branch(location_id id, bool branch, coverage_distance_type distance) {
    branching_coverage_info info(id);
    info.covered_branch = branch;

    if (std::isnan(distance)) {
        distance = std::numeric_limits<coverage_distance_type>::max();
    }
    info.distance_to_uncovered_branch = distance;
        
    INVARIANT(info.distance_to_uncovered_branch > (coverage_distance_type) 0);
    iomodels::on_branching(info);
}

static void sbt_fizzer_terminate() {
    throw terminate_exception("");
}

static void sbt_fizzer_reach_error() {
    throw error_reached_exception("Error reached");
}

extern "C" {

void __sbt_fizzer_process_branch(location_id id, bool branch, coverage_distance_type distance) {
    sbt_fizzer_process_branch(id, branch, distance);
}

void __sbt_fizzer_terminate() {
    sbt_fizzer_terminate();
}

void __sbt_fizzer_reach_error() {
    sbt_fizzer_reach_error();
}

}

}