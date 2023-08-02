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

namespace  fuzzing {


analysis_outcomes  run(
        connection::benchmark_executor&  benchmark_executor,
        execution_record_writer&  save_execution_record,
        std::function<void(execution_record const&)> const&  collector_of_boundary_violations,
        fuzzing::termination_info const&  info
        )
{
    TMPROF_BLOCK();

    analysis_outcomes  results;

    fuzzer f{ info };

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
            if (f.round_end(record))
            {
                save_execution_record(record);

                ++results.num_generated_tests;
                if ((record.flags & execution_record::EXECUTION_CRASHES) != 0)
                    ++results.num_crashes;
                if ((record.flags & execution_record::BOUNDARY_CONDITION_VIOLATION) != 0)
                {
                    collector_of_boundary_violations(record);
        
                    ++results.num_boundary_violations;
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
    results.sensitivity_statistics = f.get_sensitivity_statistics();
    results.typed_minimization_statistics = f.get_typed_minimization_statistics();
    results.minimization_statistics = f.get_minimization_statistics();
    results.bitshare_statistics = f.get_bitshare_statistics();
    results.statistics = f.get_fuzzer_statistics();

    return  results;
}


}
