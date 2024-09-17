#include <fuzzing/fuzzing_loop.hpp>
#include <fuzzing/fuzzer.hpp>
#include <fuzzing/execution_record.hpp>
#include <iomodels/iomanager.hpp>
#include <connection/client_crash_exception.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>
#include <utility/timeprof.hpp>
#include <utility/config.hpp>
#include <algorithm>
#include <tuple>

namespace  fuzzing {


analysis_outcomes  run(
        connection::benchmark_executor&  benchmark_executor,
        sala::Program const* const sala_program_ptr,
        execution_record_writer&  save_execution_record,
        std::function<void(execution_record const&)> const&  collector_of_boundary_violations,
        fuzzing::termination_info const&  info
        )
{
    TMPROF_BLOCK();

    struct  local
    {
        static void  fill_record(execution_record&  record)
        {
            record.stdin_bytes = iomodels::iomanager::instance().get_stdin()->get_bytes();
            record.stdin_types = iomodels::iomanager::instance().get_stdin()->get_types();
            for (branching_coverage_info const&  info : iomodels::iomanager::instance().get_trace())
                record.path.push_back({ info.id, info.direction });
        }
    };

    analysis_outcomes  results;
    std::unordered_set<natural_64_bit>  hashes_of_crashes;
    std::unordered_set<location_id::id_type>  exit_locations_of_boundary_violations;

    fuzzer f{ info, sala_program_ptr };

    try
    {
        while (true)
        {
            if (!f.round_begin(results.termination_reason))
            {
                results.termination_type = analysis_outcomes::TERMINATION_TYPE::NORMAL;
                break;
            }

            {
                TMPROF_BLOCK();
                benchmark_executor();
            }

            execution_record  record;
            std::tie(record.flags, record.analysis_name) = f.round_end();

            if ((record.flags & (execution_record::BRANCH_DISCOVERED  |
                                 execution_record::BRANCH_COVERED     |
                                 execution_record::EMPTY_STARTUP_TRACE)) != 0)
            {
                local::fill_record(record);
                save_execution_record(record);
                ++results.output_statistics[record.analysis_name].num_generated_tests;

                if ((record.flags & execution_record::EXECUTION_CRASHES) != 0)
                {
                    hashes_of_crashes.insert(compute_hash(record.path));
                    ++results.output_statistics[record.analysis_name].num_crashes;
                }
                else if ((record.flags & execution_record::BOUNDARY_CONDITION_VIOLATION) != 0)
                {
                    exit_locations_of_boundary_violations.insert(record.path.back().first.id);
                    collector_of_boundary_violations(record);
                    ++results.output_statistics[record.analysis_name].num_boundary_violations;
                }
            }
            else if ((record.flags & execution_record::EXECUTION_CRASHES) != 0)
            {
                local::fill_record(record);
                if (hashes_of_crashes.insert(compute_hash(record.path)).second)
                {
                    save_execution_record(record);
                    ++results.output_statistics[record.analysis_name].num_generated_tests;
                    ++results.output_statistics[record.analysis_name].num_crashes;
                }
            }
            else if ((record.flags & execution_record::BOUNDARY_CONDITION_VIOLATION) != 0)
            {
                local::fill_record(record);
                if (exit_locations_of_boundary_violations.insert(record.path.back().first.id).second)
                {
                    collector_of_boundary_violations(record);
                    ++results.output_statistics[record.analysis_name].num_boundary_violations;
                }
            }
        }
    }
    catch (connection::client_crash_exception const&  e)
    {
        results.termination_type = analysis_outcomes::TERMINATION_TYPE::CLIENT_COMMUNICATION_ERROR;
        results.error_message = e.what();
    }
    catch (std::exception const&  e)
    {
        results.termination_type = analysis_outcomes::TERMINATION_TYPE::SERVER_INTERNAL_ERROR;
        results.error_message = e.what();
    }

    if (results.termination_type != analysis_outcomes::TERMINATION_TYPE::NORMAL)
    {
        try { f.terminate(); } catch (...) {}
    }

    results.num_executions = f.get_performed_driver_executions();
    results.num_elapsed_seconds = f.get_elapsed_seconds();
    results.covered_branchings.assign(f.get_covered_branchings().begin(), f.get_covered_branchings().end());
    std::sort(results.covered_branchings.begin(),results.covered_branchings.end());
    results.uncovered_branchings.assign(f.get_uncovered_branchings().begin(), f.get_uncovered_branchings().end());
    std::sort(results.uncovered_branchings.begin(),results.uncovered_branchings.end());
    results.input_flow_statistics = f.get_input_flow_statistics();
    results.sensitivity_statistics = f.get_sensitivity_statistics();
    results.typed_minimization_statistics = f.get_typed_minimization_statistics();
    results.minimization_statistics = f.get_minimization_statistics();
    results.bitshare_statistics = f.get_bitshare_statistics();
    results.fuzzer_statistics = f.get_fuzzer_statistics();

    return  results;
}


}
