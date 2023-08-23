#include <fuzzing/optimizer.hpp>
#include <fuzzing/optimization_outcomes.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/std_pair_hash.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>
#include <vector>
#include <unordered_set>

namespace  fuzzing {


optimizer::optimizer(configuration const&  cfg)
    : config{ cfg }

    , time_point_start{}
    , time_point_current{}

    , statistics{}
{}


optimization_outcomes  optimizer::run(
        std::vector<vecu8> const&  inputs_leading_to_boundary_violation,
        std::vector<location_id> const&  already_covered_branchings,
        std::vector<branching_location_and_direction> const&  already_uncovered_branchings,
        connection::benchmark_executor&  benchmark_executor,
        execution_record_writer&  save_execution_record
        )
{
    time_point_start = std::chrono::steady_clock::now();
    time_point_current = time_point_start;

    optimization_outcomes  outcomes;
    outcomes.termination_type = optimization_outcomes::TERMINATION_TYPE::NORMAL;
    outcomes.termination_reason = TERMINATION_REASON::ALL_TESTS_WERE_PROCESSED;

    std::unordered_set<natural_64_bit>  hashes_of_crashes;

    if (!inputs_leading_to_boundary_violation.empty())
    {

        std::unordered_set<location_id>  covered_branchings{
                already_covered_branchings.begin(), already_covered_branchings.end()
                };
        std::unordered_set<branching_location_and_direction>  uncovered_branchings{
                already_uncovered_branchings.begin(), already_uncovered_branchings.end()
                };

        std::unordered_set<location_id>  extra_covered_branchings;
        std::unordered_set<branching_location_and_direction>  extra_uncovered_branchings;

        for (vecu8 const&  stdin_bytes : inputs_leading_to_boundary_violation)
        {
            time_point_current = std::chrono::steady_clock::now();
            if (num_remaining_seconds() <= 0L)
            {
                outcomes.termination_reason = TERMINATION_REASON::TIME_BUDGET_DEPLETED;
                break;
            }

            iomodels::iomanager::instance().get_stdin()->clear();
            iomodels::iomanager::instance().get_stdout()->clear();
            iomodels::iomanager::instance().get_stdin()->set_bytes(stdin_bytes);

            try
            {
                benchmark_executor();
            }
            catch (std::exception const&  e)
            {
                outcomes.termination_type = optimization_outcomes::TERMINATION_TYPE::SERVER_INTERNAL_ERROR;
                outcomes.error_message = e.what();
                break;
            }

            ++statistics.num_executions;

            bool  trace_any_location_discovered = false;
            std::unordered_set<location_id>  trace_covered_branchings;
            {
                for (branching_coverage_info const&  info : iomodels::iomanager::instance().get_trace())
                {
                    if (!covered_branchings.contains(info.id))
                    {
                        auto const  it_along = uncovered_branchings.find({ info.id, info.direction });
                        if (it_along == uncovered_branchings.end())
                        {
                            auto const  it_escape = uncovered_branchings.find({ info.id, !info.direction });
                            if (it_escape == uncovered_branchings.end())
                            {
                                extra_uncovered_branchings.insert({ info.id, !info.direction });
                                trace_any_location_discovered = true;

                                uncovered_branchings.insert({ info.id, !info.direction });
                            }
                        }
                        else
                        {
                            extra_uncovered_branchings.erase(*it_along);
                            extra_covered_branchings.insert(info.id);

                            trace_covered_branchings.insert(info.id);

                            uncovered_branchings.erase(it_along);
                            covered_branchings.insert(info.id);
                        }
                    }
                }
            }

            execution_record::execution_flags  exe_flags;
            {
                exe_flags = 0;

                if (iomodels::iomanager::instance().get_termination() == instrumentation::target_termination::crash)
                    exe_flags |= execution_record::EXECUTION_CRASHES;

                if (iomodels::iomanager::instance().get_termination() == instrumentation::target_termination::boundary_condition_violation)
                    exe_flags |= execution_record::BOUNDARY_CONDITION_VIOLATION;

                if (trace_any_location_discovered)
                    exe_flags |= execution_record::BRANCH_DISCOVERED;

                if (!trace_covered_branchings.empty())
                    exe_flags |= execution_record::BRANCH_COVERED;
            }

            bool const  is_path_worth_recording =
                    exe_flags & (execution_record::BRANCH_DISCOVERED | execution_record::BRANCH_COVERED | execution_record::EXECUTION_CRASHES);

            if (is_path_worth_recording)
            {
                execution_record record;
                {
                    record.flags |= exe_flags;
                    record.stdin_bytes = iomodels::iomanager::instance().get_stdin()->get_bytes();
                    record.stdin_types = iomodels::iomanager::instance().get_stdin()->get_types();
                    record.path.clear();
                    for (branching_coverage_info const&  info : iomodels::iomanager::instance().get_trace())
                        record.path.push_back({ info.id, info.direction });
                }

                bool const  is_saved_crash{
                        (exe_flags & execution_record::EXECUTION_CRASHES) != 0 &&
                        !hashes_of_crashes.insert(compute_hash(record.path)).second
                        };

                if (!is_saved_crash)
                {
                    save_execution_record(record);

                    ++statistics.num_extended_tests;
                }
            }
        }

        outcomes.covered_branchings.assign(extra_covered_branchings.begin(), extra_covered_branchings.end());
        std::sort(outcomes.covered_branchings.begin(),outcomes.covered_branchings.end());
        outcomes.uncovered_branchings.assign(extra_uncovered_branchings.begin(), extra_uncovered_branchings.end());
        std::sort(outcomes.uncovered_branchings.begin(),outcomes.uncovered_branchings.end());
    }

    outcomes.statistics = statistics;

    time_point_current = std::chrono::steady_clock::now();
    statistics.num_seconds = get_elapsed_seconds();

    return outcomes;
}


}
