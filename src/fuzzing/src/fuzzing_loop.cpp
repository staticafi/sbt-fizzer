#include <fuzzing/fuzzing_loop.hpp>
#include <fuzzing/fuzzer.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>
#include <utility/timeprof.hpp>
#include <utility/config.hpp>
#include <algorithm>

namespace  fuzzing {


analysis_outcomes  run(std::function<void()> const&  benchmark_executor, termination_info const&  info, bool const  debug_mode)
{
    TMPROF_BLOCK();

    analysis_outcomes  results;
    results.execution_records.push_back({});

    fuzzer f{ info, debug_mode };

    try
    {
        while (true)
        {
            TMPROF_BLOCK();

            if (!f.round_begin(results.termination_reason))
            {
                results.termination_type = analysis_outcomes::TERMINATION_TYPE::NORMAL;
                break;
            }

            benchmark_executor();

            if (f.round_end(results.execution_records.back()))
                results.execution_records.push_back({});
        }
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

    results.execution_records.pop_back();

    results.num_executions = f.get_performed_driver_executions();
    results.num_elapsed_seconds = f.get_elapsed_seconds();
    results.covered_branchings.assign(f.get_covered_branchings().begin(), f.get_covered_branchings().end());
    std::sort(results.covered_branchings.begin(),results.covered_branchings.end());
    results.uncovered_branchings.assign(f.get_uncovered_branchings().begin(), f.get_uncovered_branchings().end());
    std::sort(results.uncovered_branchings.begin(),results.uncovered_branchings.end());
    results.sensitivity_statistics = f.get_sensitivity_statistics();
    results.minimization_statistics = f.get_minimization_statistics();
    results.bitshare_statistics = f.get_bitshare_statistics();
    results.statistics = f.get_fuzzer_statistics();
    if (debug_mode)
        results.debug_data = f.get_debug_data();

    return  results;
}


}
