#include <fuzzing/fuzzing_loop.hpp>
#include <fuzzing/fuzzer.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>
#include <utility/timeprof.hpp>
#include <utility/config.hpp>
#include <connection/kleeient_connector.hpp>
#include <algorithm>

namespace  fuzzing {


analysis_outcomes  run(std::function<void()> const&  benchmark_executor,
                       std::unique_ptr<connection::kleeient_connector> kleeient_connector,
                       termination_info const&  info,
                       bool const  debug_mode)
{
    TMPROF_BLOCK();

    analysis_outcomes  results;
    results.execution_records.push_back({});

    fuzzer f{ info, std::move(kleeient_connector), debug_mode, true };

#if BUILD_RELEASE() == 1
    try
#endif
    {
        while (true)
        {
            TMPROF_BLOCK();

            results.termination_message = f.round_begin();
            if (!results.termination_message.empty())
            {
                results.termination_type = analysis_outcomes::TERMINATION_TYPE::NORMAL;
                break;
            }

            benchmark_executor();

            if (f.round_end(results.execution_records.back()))
                results.execution_records.push_back({});
        }
    }
#if BUILD_RELEASE() == 1
    catch (invariant_failure const& e)
    {
        results.termination_type = analysis_outcomes::TERMINATION_TYPE::SERVER_INTERNAL_ERROR;
        results.termination_message = e.what();
    }
    catch (assumption_failure const& e)
    {
        results.termination_type = analysis_outcomes::TERMINATION_TYPE::SERVER_INTERNAL_ERROR;
        results.termination_message = e.what();
    }
    catch (under_construction const& e)
    {
        results.termination_type = analysis_outcomes::TERMINATION_TYPE::SERVER_INTERNAL_ERROR;
        results.termination_message = e.what();
    }
    catch (std::exception const&  e)
    {
        results.termination_type = analysis_outcomes::TERMINATION_TYPE::UNCLASSIFIED_ERROR;
        results.termination_message = e.what();
    }
#endif

    if (results.termination_type != analysis_outcomes::TERMINATION_TYPE::NORMAL)
    {
#if BUILD_RELEASE() == 1
        try {
#endif
            f.terminate();
#if BUILD_RELEASE() == 1
        } catch (...) {}
#endif
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
    results.jetklee_statistics = f.get_jetklee_statistics();
    results.statistics = f.get_fuzzer_statistics();
    results.analysis_statistics = f.get_analysis_statistics();
    if (debug_mode)
        results.debug_data = f.get_debug_data();

    return  results;
}


}
