#include <fuzzing/fuzzing_loop.hpp>
#include <connection/server.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>
#include <utility/timeprof.hpp>
#include <utility/config.hpp>
#include <algorithm>

namespace  fuzzing {


analysis_outcomes  run(connection::server& server, std::shared_ptr<fuzzer_base> const  fuzzer)
{
    TMPROF_BLOCK();

    ASSUMPTION(fuzzer != nullptr);

    analysis_outcomes  results;

    try
    {
        while (true)
        {
            TMPROF_BLOCK();
            std::cout << "Running fuzzing loop body" << std::endl;
            fuzzer->_on_driver_begin();
            server.wait_for_client();
            server.send_input_to_client_and_receive_result();
            fuzzer->_on_driver_end();
            std::cout << "Loop body ran" << std::endl;
        }
    }
    catch (fuzzer_interrupt_exception const& e)
    {
        results.termination_type = analysis_outcomes::TERMINATION_TYPE::NORMAL;
        results.termination_message = e.what();
    }
#if BUILD_RELEASE() == 1
    catch (invariant_failure const& e)
    {
        results.termination_type = analysis_outcomes::TERMINATION_TYPE::INVARIANT_FAILURE;
        results.termination_message = e.what();
    }
    catch (assumption_failure const& e)
    {
        results.termination_type = analysis_outcomes::TERMINATION_TYPE::ASSUMPTION_FAILURE;
        results.termination_message = e.what();
    }
    catch (under_construction const& e)
    {
        results.termination_type = analysis_outcomes::TERMINATION_TYPE::CODE_UNDER_CONSTRUCTION_REACHED;
        results.termination_message = e.what();
    }
    catch (std::exception const&  e)
    {
        results.termination_type = analysis_outcomes::TERMINATION_TYPE::UNCLASSIFIED_EXCEPTION;
        results.termination_message = e.what();
    }
#endif

    results.num_executions = fuzzer->get_performed_driver_executions();
    results.num_elapsed_seconds = fuzzer->get_elapsed_seconds();

    for (auto const& id_and_info : fuzzer->get_branch_coverage_info())
        if (id_and_info.second.true_branch_covered && id_and_info.second.false_branch_covered)
            results.covered_branchings.push_back(id_and_info.first);
    std::sort(results.covered_branchings.begin(),results.covered_branchings.end());

    for (auto const& id_and_info : fuzzer->get_branch_coverage_info())
        if (!id_and_info.second.true_branch_covered)
            results.uncovered_branchings.emplace_back( id_and_info.first, true);
        else if (!id_and_info.second.false_branch_covered)
            results.uncovered_branchings.emplace_back( id_and_info.first, false);
    std::sort(results.uncovered_branchings.begin(),results.uncovered_branchings.end());

    results.traces_forming_coverage = fuzzer->get_traces_forming_coverage();

    return  results;
}


}
