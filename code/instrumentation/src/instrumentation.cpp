#include <utility/basic_numeric_types.hpp>
#include <instrumentation/instrumentation_types.hpp>
#include <iomodels/instrumentation_callbacks.hpp>
#include <utility/invariants.hpp>
#include <cmath>

namespace instrumentation {

extern "C" {
void __sbt_fizzer_process_branch(location_id id, bool branch, coverage_distance_type distance) {
    branching_coverage_info info(id);
    info.covered_branch = branch;

    if (std::isnan(distance)) {
        distance = std::numeric_limits<coverage_distance_type>::max();
    }
    info.distance_to_uncovered_branch = distance;
        
    INVARIANT(info.distance_to_uncovered_branch > (coverage_distance_type) 0);
    iomodels::on_branching(info);
}

void __sbt_fizzer_terminate() {
    throw terminate_exception("");
}

void __sbt_fizzer_reach_error() {
    throw error_reached_exception("Error reached");
}
}

}