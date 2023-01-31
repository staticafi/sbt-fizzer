#include <fuzzing/fuzzer_base.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/assumptions.hpp>

namespace  fuzzing {


fuzzer_base::fuzzer_base(termination_info const&  info)
    : termination_props(info)
    , num_driver_executions(0U)
    , num_max_trace_size_reached(0U)
    , time_point_start(std::chrono::steady_clock::now())
    , time_point_current(time_point_start)
    , generator(0U)
    , coverage_info()
    , num_uncovered_branchings(0U)
    , last_trace_covered_branchings()
    , last_trace_discovered_branchings()
    , last_trace_uncovered_branchings()
    , fuzzing_strategy_finished(false)
{}


void  fuzzer_base::_on_driver_begin()
{
    if (get_performed_driver_executions() > 0U && get_num_uncovered_branchings() == 0U) {
        if (get_num_max_trace_size_reached() > 0U) {
            throw fuzzer_interrupt_exception("All reachable branchings were covered given the maximum trace size.");
        }
        throw fuzzer_interrupt_exception("All reachable branchings were covered.");
    }

    if (num_remaining_seconds() <= 0L)
        throw fuzzer_interrupt_exception("Max number of seconds for fuzzing was reached.");

    if (num_remaining_driver_executions() <= 0L)
        throw fuzzer_interrupt_exception("Max mumber of benchmark executions reached.");

    if (fuzzing_strategy_finished && !get_termination_info().allow_blind_fuzzing)
        throw fuzzer_interrupt_exception("The fuzzing strategy has finished and blind fuzzing is not allowed.");

    iomodels::iomanager::instance().clear_trace();
    iomodels::iomanager::instance().clear_stdin();
    iomodels::iomanager::instance().clear_stdout();

    on_execution_begin();

    ASSUMPTION(iomodels::iomanager::instance().get_stdin()->get_bits().size() <=
               iomodels::iomanager::instance().get_stdin()->get_max_bits());
}


void  fuzzer_base::_on_driver_end()
{
    last_trace_covered_branchings.clear();
    last_trace_discovered_branchings.clear();
    last_trace_uncovered_branchings.clear();

    std::vector<branching_coverage_info> const&  trace = iomodels::iomanager::instance().get_trace(); 
    for (natural_32_bit  i = 0U, n = (natural_32_bit)trace.size(); i != n; ++i)
    {
        branching_coverage_info const&  info = trace.at(i); 

        auto it = coverage_info.find(info.branching_id);
        if (it == coverage_info.end())
        {
            coverage_info.insert({
                    info.branching_id,
                    info.covered_branch ? branch_coverage_info{ true, false } :
                                          branch_coverage_info{ false, true }
                    });
            ++num_uncovered_branchings;
            last_trace_discovered_branchings[info.branching_id].insert(i);;
            last_trace_uncovered_branchings[info.branching_id].insert(i);
        }
        else
        {
            std::pair<bool&,bool&>  taken_and_other_branch = info.covered_branch ?
                    std::pair<bool&,bool&>{ it->second.true_branch_covered, it->second.false_branch_covered } :
                    std::pair<bool&,bool&>{ it->second.false_branch_covered, it->second.true_branch_covered } ;
            if (!taken_and_other_branch.first)
            {
                taken_and_other_branch.first = true;
                --num_uncovered_branchings;
                last_trace_covered_branchings.insert(info.branching_id);
                last_trace_discovered_branchings.erase(info.branching_id);
                last_trace_uncovered_branchings.erase(info.branching_id);
            }
            else if (!taken_and_other_branch.second)
                last_trace_uncovered_branchings[info.branching_id].insert(i);
        }
    }

    if (!get_last_trace_discovered_branchings().empty() || !get_last_trace_covered_branchings().empty())
    {
        traces_forming_coverage.push_back(trace_with_coverage_info{
                iomodels::iomanager::instance().get_stdin()->get_bits(),
                iomodels::iomanager::instance().get_stdin()->get_counts(),
                {},
                {},
                get_last_trace_covered_branchings()
                });
        for (branching_coverage_info const&  info : trace)
            traces_forming_coverage.back().trace.push_back({ info.branching_id, info.covered_branch }); 
        for (auto const&  loc_and_indices : get_last_trace_discovered_branchings())
            traces_forming_coverage.back().discovered_locations.insert(loc_and_indices.first);
    }

    on_execution_end();

    if (iomodels::iomanager::instance().received_message_type == 
        connection::message_type::results_from_client_max_trace_reached) {
        ++num_max_trace_size_reached;
    }
    time_point_current = std::chrono::steady_clock::now();
    ++num_driver_executions;
}


}
