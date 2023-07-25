#include <fuzzing/fuzzer.hpp>
#include <fuzzing/dump_tree.hpp>
#include <fuzzing/progress_recorder.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>

namespace  fuzzing {


fuzzer::primary_coverage_target_branchings::primary_coverage_target_branchings(
        std::function<bool(location_id)> const&  is_covered_,
        std::function<bool(location_id)> const&  is_iid_
        )
    : sensitive{}
    , untouched{}
    , iid_twins{}
    , is_covered{ is_covered_ }
    , is_iid{ is_iid_ }
{}


void  fuzzer::primary_coverage_target_branchings::process_potential_coverage_target(branching_node* const  node)
{
    ASSUMPTION(node != nullptr);
    if (node->is_open_branching() && !is_covered(node->get_location_id()))
    {
        if (node->sensitivity_performed)
        {
            if (!node->sensitive_stdin_bits.empty() && (!node->bitshare_performed || !node->minimization_performed))
                sensitive.insert(node);
        }
        else
        {
            if (is_iid(node->get_location_id()))
                iid_twins.insert(node);
            else
                untouched.insert(node);
        }
    }
}


void  fuzzer::primary_coverage_target_branchings::erase(branching_node* const  node)
{
    ASSUMPTION(node != nullptr);
    sensitive.erase(node);
    untouched.erase(node);
    iid_twins.erase(node);
}


bool  fuzzer::primary_coverage_target_branchings::empty() const
{
    return sensitive.empty() && untouched.empty() && iid_twins.empty();
}


void  fuzzer::primary_coverage_target_branchings::clear()
{
    sensitive.clear();
    untouched.clear();
    iid_twins.clear();
}


void  fuzzer::primary_coverage_target_branchings::do_cleanup()
{
    std::unordered_set<branching_node*>  work_set{ sensitive.begin(), sensitive.end() };
    work_set.insert(untouched.begin(), untouched.end());
    work_set.insert(iid_twins.begin(), iid_twins.end());
    clear();
    while (!work_set.empty())
    {
        branching_node* const  node = *work_set.begin();
        work_set.erase(work_set.begin());
        process_potential_coverage_target(node);
    }
}


branching_node*  fuzzer::primary_coverage_target_branchings::get_best()
{
    struct  branching_node_with_less_than
    {
        branching_node_with_less_than(branching_node* const  node_) : node{ node_ } {}
        operator  branching_node*() const { return node; }
        bool  operator<(branching_node_with_less_than const&  other) const
        {
            if (node->sensitivity_performed && !other.node->sensitivity_performed)
                return true;
            if (!node->sensitivity_performed && other.node->sensitivity_performed)
                return false;
            if (node->sensitive_stdin_bits.size() < other.node->sensitive_stdin_bits.size())
                return true;
            if (node->sensitive_stdin_bits.size() > other.node->sensitive_stdin_bits.size())
                return false;
            if (node->get_num_stdin_bytes() < other.node->get_num_stdin_bytes())
                return true;
            if (node->get_num_stdin_bytes() > other.node->get_num_stdin_bytes())
                return false;
            if (node->trace_index < other.node->trace_index)
                return true;
            if (node->trace_index > other.node->trace_index)
                return false;
            return node->max_successors_trace_index > other.node->max_successors_trace_index;
        }
    private:
        branching_node*  node;
    };
    for (auto* const  targets : { &sensitive, &untouched, &iid_twins })
        if (!targets->empty())
        {
            branching_node_with_less_than  best{ *targets->begin() };
            for (auto  it = std::next(targets->begin()); it != targets->end(); ++it)
            {
                branching_node_with_less_than const  current{ *it };
                if (current < best)
                    best = current;
            }
            return best;
        }
    return nullptr;
}


void  fuzzer::update_close_flags_from(branching_node* const  node)
{
    if (node->is_closed() || node->is_open_branching())
        return;
    branching_node::successor_pointer const&  left = node->successor(false);
    if (left.pointer != nullptr && !left.pointer->is_closed())
        return;
    branching_node::successor_pointer const&  right = node->successor(true);
    if (right.pointer != nullptr && !right.pointer->is_closed())
        return;

    node->set_closed();

    if (node->predecessor != nullptr)
        update_close_flags_from(node->predecessor);
}


fuzzer::fuzzer(termination_info const&  info, bool const  debug_mode_)
    : termination_props{ info }

    , num_driver_executions{ 0U }
    , time_point_start{ std::chrono::steady_clock::now() }
    , time_point_current{ time_point_start }

    , entry_branching{}
    , leaf_branchings{}

    , covered_branchings{}
    , uncovered_branchings{}
    , branchings_to_crashes{}

    , primary_coverage_targets{
            [this](location_id const  id) { return covered_branchings.contains(id); },
            [this](location_id const  id) { return iid_pivots.contains(id); }                    
            }
    , iid_pivots{}

    , coverage_failures_with_hope{}

    , state{ STARTUP }
    , sensitivity{}
    , typed_minimization{}
    , minimization{}
    , bitshare{}

    , statistics{}

    , debug_mode{ debug_mode_ }
    , debug_data{}
{}


fuzzer::~fuzzer()
{
    terminate();
}


void  fuzzer::terminate()
{
    stop_all_analyzes();
    while (!leaf_branchings.empty())
        remove_leaf_branching_node(*leaf_branchings.begin());
}


void  fuzzer::stop_all_analyzes()
{
    sensitivity.stop();
    typed_minimization.stop();
    minimization.stop();
    bitshare.stop();
}


bool  fuzzer::round_begin(TERMINATION_REASON&  termination_reason)
{
    TMPROF_BLOCK();

    if (get_performed_driver_executions() > 0U)
    {
        if (uncovered_branchings.empty())
        {
            stop_all_analyzes();
            debug_save_branching_tree("final");
            terminate();
            termination_reason = TERMINATION_REASON::ALL_REACHABLE_BRANCHINGS_COVERED;
            return false;
        }
    }

    if (num_remaining_seconds() <= 0L)
    {
        stop_all_analyzes();
        debug_save_branching_tree("final");
        terminate();
        termination_reason = TERMINATION_REASON::TIME_BUDGET_DEPLETED;
        return false;
    }

    if (num_remaining_driver_executions() <= 0L)
    {
        stop_all_analyzes();
        debug_save_branching_tree("final");
        terminate();
        termination_reason = TERMINATION_REASON::EXECUTIONS_BUDGET_DEPLETED;
        return false;
    }

    iomodels::iomanager::instance().get_stdin()->clear();
    iomodels::iomanager::instance().get_stdout()->clear();

    vecb  stdin_bits;
    generate_next_input(stdin_bits);
    if (!can_make_progress())
    {
        stop_all_analyzes();
        debug_save_branching_tree("final");
        terminate();
        termination_reason = TERMINATION_REASON::FUZZING_STRATEGY_DEPLETED;
        return false;
    }
    vecu8 stdin_bytes;
    bits_to_bytes(stdin_bits, stdin_bytes);
    iomodels::iomanager::instance().get_stdin()->set_bytes(stdin_bytes);

    recorder().on_input_generated();

    return true;
}


bool  fuzzer::round_end(execution_record&  record)
{
    TMPROF_BLOCK();

    execution_record::execution_flags const  flags = process_execution_results();

    bool const  is_path_worth_recording =
            flags & (execution_record::BRANCH_DISCOVERED | execution_record::BRANCH_COVERED | execution_record::EXECUTION_CRASHES);

    if (is_path_worth_recording)
    {
        record.flags = flags;
        record.stdin_bytes = iomodels::iomanager::instance().get_stdin()->get_bytes();
        record.stdin_types = iomodels::iomanager::instance().get_stdin()->get_types();
        for (branching_coverage_info const&  info : iomodels::iomanager::instance().get_trace())
            record.path.push_back({ info.id, info.direction });
    }

    time_point_current = std::chrono::steady_clock::now();
    ++num_driver_executions;

    return is_path_worth_recording;
}


void  fuzzer::debug_save_branching_tree(std::string const&  stage_name) const
{
    if (debug_mode == false)
        return;

    std::string const  suffix = '_' + stage_name + ".dot";
    if (debug_data.contains(suffix))
        return;

    std::stringstream  sstr;
    dump_subtree_dot(entry_branching, sstr);
    debug_data.insert({ suffix, sstr.str() });
}


void  fuzzer::generate_next_input(vecb&  stdin_bits)
{
    TMPROF_BLOCK();

    while (true)
    {
        switch (state)
        {
            case STARTUP:
                if (get_performed_driver_executions() == 0U)
                    return;
                break;

            case SENSITIVITY:
                if (sensitivity.generate_next_input(stdin_bits))
                    return;
                break;

            case TYPED_MINIMIZATION:
                if (typed_minimization.generate_next_input(stdin_bits))
                    return;
                break;

            case MINIMIZATION:
                if (minimization.generate_next_input(stdin_bits))
                    return;
                break;

            case BITSHARE:
                if (bitshare.generate_next_input(stdin_bits))
                    return;
                break;

            case FINISHED:
                if (!apply_coverage_failures_with_hope())
                    return;
                break;

            default: { UNREACHABLE(); break; }
        }

        do_cleanup();
        select_next_state();

        stdin_bits.clear();
    }

    UNREACHABLE();
}


execution_record::execution_flags  fuzzer::process_execution_results()
{
    TMPROF_BLOCK();

    if (state == FINISHED)
        return false;

    if (iomodels::iomanager::instance().get_trace().empty())
    {
        state = FINISHED;
        return true; // the analyzed program has exactly 1 trace.
    }

    stdin_bits_and_types_pointer const  bits_and_types{ std::make_shared<stdin_bits_and_types>(
            iomodels::iomanager::instance().get_stdin()->get_bytes(),
            iomodels::iomanager::instance().get_stdin()->get_types()
            ) };
    execution_trace_pointer const  trace = std::make_shared<execution_trace>(iomodels::iomanager::instance().get_trace());
    br_instr_execution_trace_pointer const  br_instr_trace = std::make_shared<br_instr_execution_trace>(iomodels::iomanager::instance().get_br_instr_trace());

    leaf_branching_construction_props  construction_props;

    if (entry_branching == nullptr)
    {
        entry_branching = new branching_node(
                trace->front().id,
                0,
                trace->front().num_input_bytes,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                std::numeric_limits<branching_function_value_type>::max(),
                std::numeric_limits<branching_function_value_type>::max(),
                num_driver_executions,
                trace->front().xor_like_branching_function
                );
        construction_props.diverging_node = entry_branching;

        ++statistics.nodes_created;
    }

    construction_props.leaf = entry_branching;
    branching_function_value_type  summary_value = 0.0;

    trace_index_type  trace_index = 0;
    for (; true; ++trace_index)
    {
        branching_coverage_info const&  info = trace->at(trace_index);

        INVARIANT(construction_props.leaf->id == info.id);

        if (covered_branchings.count(info.id) == 0)
        {
            auto const  it_along = uncovered_branchings.find({ info.id, info.direction });
            if (it_along == uncovered_branchings.end())
            {
                auto const  it_escape = uncovered_branchings.find({ info.id, !info.direction });
                if (it_escape == uncovered_branchings.end())
                {
                    uncovered_branchings.insert({ info.id, !info.direction });
                    construction_props.any_location_discovered = true;
                }

                construction_props.uncovered_locations[info.id].insert(construction_props.leaf);
            }
            else
            {
                uncovered_branchings.erase(it_along);
                covered_branchings.insert(info.id);

                construction_props.uncovered_locations.erase(info.id);
                construction_props.covered_locations.insert(info.id);
            }
        }

        summary_value += info.value * info.value;
        bool const  value_ok = std::isfinite(summary_value);
        if (construction_props.leaf->best_stdin == nullptr || (value_ok && construction_props.leaf->best_summary_value > summary_value))
        {
            construction_props.leaf->best_stdin = bits_and_types;
            construction_props.leaf->best_trace = trace;
            construction_props.leaf->best_br_instr_trace = br_instr_trace;
            construction_props.leaf->best_coverage_value =
                    value_ok ? info.value : std::numeric_limits<branching_function_value_type>::max();
            construction_props.leaf->best_summary_value =
                    value_ok ? summary_value : std::numeric_limits<branching_function_value_type>::max();
            construction_props.leaf->best_value_execution = num_driver_executions;
        }

        construction_props.leaf->max_successors_trace_index = std::max(
                construction_props.leaf->max_successors_trace_index,
                (trace_index_type)(trace->size() - 1)
                );

        if (trace_index + 1 == trace->size())
            break;

        if (construction_props.leaf->successor(info.direction).pointer == nullptr)
        {
            branching_coverage_info const&  succ_info = trace->at(trace_index + 1);
            construction_props.leaf->set_successor(info.direction, {
                branching_node::successor_pointer::VISITED,
                new branching_node(
                    succ_info.id,
                    trace_index + 1,
                    succ_info.num_input_bytes,
                    construction_props.leaf,
                    bits_and_types,
                    trace,
                    br_instr_trace,
                    succ_info.value,
                    succ_info.value * succ_info.value,
                    num_driver_executions,
                    succ_info.xor_like_branching_function
                    )
            });

            ++statistics.nodes_created;

            if (construction_props.diverging_node == nullptr)
                construction_props.diverging_node = construction_props.leaf->successor(info.direction).pointer;
        }

        construction_props.leaf = construction_props.leaf->successor(info.direction).pointer;
    }

    construction_props.leaf->set_successor(trace->back().direction, {
        std::max(
            iomodels::iomanager::instance().get_termination() == instrumentation::target_termination::normal ?
                branching_node::successor_pointer::END_NORMAL :
                branching_node::successor_pointer::END_EXCEPTIONAL,
            construction_props.leaf->successor(trace->back().direction).label
            ),
        construction_props.leaf->successor(trace->back().direction).pointer
    });

    if (construction_props.diverging_node != nullptr)
    {
        auto const  it_and_state = leaf_branchings.insert(construction_props.leaf);
        INVARIANT(it_and_state.second);

        for (branching_node*  node = construction_props.leaf; node != construction_props.diverging_node->predecessor; node = node->predecessor)
            primary_coverage_targets.process_potential_coverage_target(node);

        ++statistics.leaf_nodes_created;
        statistics.max_leaf_nodes = std::max(statistics.max_leaf_nodes, leaf_branchings.size());
        statistics.longest_branch = std::max(statistics.longest_branch, (std::size_t)(trace_index + 1));
    }
    else
        update_close_flags_from(construction_props.leaf);

    recorder().on_trace_mapped_to_tree(construction_props.leaf);

    switch (state)
    {
        case STARTUP:
            INVARIANT(sensitivity.is_ready() && typed_minimization.is_ready() && minimization.is_ready() && bitshare.is_ready());
            recorder().on_execution_results_available();
            break;

        case SENSITIVITY:
            INVARIANT(sensitivity.is_busy() && typed_minimization.is_ready() && minimization.is_ready() && bitshare.is_ready());
            recorder().on_execution_results_available();
            sensitivity.process_execution_results(trace, entry_branching);
            break;

        case TYPED_MINIMIZATION:
            INVARIANT(sensitivity.is_ready() && typed_minimization.is_busy() && minimization.is_ready() && bitshare.is_ready());
            typed_minimization.process_execution_results(trace);
            if (typed_minimization.get_node()->is_direction_explored(false) && typed_minimization.get_node()->is_direction_explored(true))
            {
                typed_minimization.stop();
                bitshare.bits_available_for_branching(typed_minimization.get_node(), trace, bits_and_types);
            }
            break;

        case MINIMIZATION:
            INVARIANT(sensitivity.is_ready() && typed_minimization.is_ready() && minimization.is_busy() && bitshare.is_ready());
            minimization.process_execution_results(trace);
            if (minimization.get_node()->is_direction_explored(false) && minimization.get_node()->is_direction_explored(true))
            {
                minimization.stop();
                bitshare.bits_available_for_branching(minimization.get_node(), trace, bits_and_types);
            }
            break;

        case BITSHARE:
            INVARIANT(sensitivity.is_ready() && typed_minimization.is_ready() && minimization.is_ready() && bitshare.is_busy());
            recorder().on_execution_results_available();
            bitshare.process_execution_results(trace);
            if (bitshare.get_node()->is_direction_explored(false) && bitshare.get_node()->is_direction_explored(true))
                bitshare.stop();
            break;

        default: UNREACHABLE(); break;
    }

    execution_record::execution_flags  exe_flags;
    {
        exe_flags = 0;

        if (iomodels::iomanager::instance().get_termination() == instrumentation::target_termination::crash)
        {
            ++statistics.traces_to_crash;

            auto const  it_and_state = branchings_to_crashes.insert(construction_props.leaf->id);
            if (it_and_state.second)
                exe_flags |= execution_record::EXECUTION_CRASHES;
        }

        if (iomodels::iomanager::instance().get_termination() == instrumentation::target_termination::boundary_condition_violation)
        {
            ++statistics.traces_to_boundary_violation;
            exe_flags |= execution_record::BOUNDARY_CONDITION_VIOLATION;
        }

        if (construction_props.any_location_discovered)
            exe_flags |= execution_record::BRANCH_DISCOVERED;

        if (!construction_props.covered_locations.empty())
            exe_flags |= execution_record::BRANCH_COVERED;
    }

    return exe_flags;
}


void  fuzzer::do_cleanup()
{
    TMPROF_BLOCK();

    INVARIANT(
        sensitivity.is_ready() &&
        bitshare.is_ready() &&
        typed_minimization.is_ready() &&
        minimization.is_ready() &&
        (state != FINISHED || !primary_coverage_targets.empty())
        );

    switch (state)
    {
        case SENSITIVITY:
            for (branching_node* node : sensitivity.get_changed_nodes())
                if (node->is_iid_branching() && !covered_branchings.contains(node->get_location_id()))
                    iid_pivots[node->get_location_id()][node->get_num_stdin_bytes()].insert({ node, {} });
            update_close_flags_from(sensitivity.get_node());
            break;
        case BITSHARE:
            update_close_flags_from(bitshare.get_node());
            break;
        case TYPED_MINIMIZATION:
            update_close_flags_from(typed_minimization.get_node());
            if (!covered_branchings.contains(typed_minimization.get_node()->get_location_id()))
                coverage_failures_with_hope.insert(typed_minimization.get_node());
            break;
        case MINIMIZATION:
            update_close_flags_from(minimization.get_node());
            if (!covered_branchings.contains(minimization.get_node()->get_location_id()))
                coverage_failures_with_hope.insert(minimization.get_node());
            break;
        default:
            break;
    }

    std::vector<branching_node*> leaves_to_remove;
    for (branching_node*  leaf : leaf_branchings)
        if (leaf->successor(false).pointer != nullptr || leaf->successor(true).pointer != nullptr)
            leaves_to_remove.push_back(leaf);
    while (!leaves_to_remove.empty())
    {
        remove_leaf_branching_node(leaves_to_remove.back());
        leaves_to_remove.pop_back();
    }

    primary_coverage_targets.do_cleanup();

    for (auto  it = iid_pivots.begin(); it != iid_pivots.end(); )
        if (covered_branchings.contains(it->first))
            it = iid_pivots.erase(it);
        else
            ++it;

    for (auto  it = coverage_failures_with_hope.begin(); it != coverage_failures_with_hope.end(); )
        if (covered_branchings.contains((*it)->id))
            it = coverage_failures_with_hope.erase(it);
        else
            ++it;
}


void  fuzzer::select_next_state()
{
    TMPROF_BLOCK();

    INVARIANT(sensitivity.is_ready() && typed_minimization.is_ready() && minimization.is_ready() && bitshare.is_ready());

    branching_node*  winner = primary_coverage_targets.get_best();

    if (winner == nullptr)
    {
        state = FINISHED;
        return;
    }

    INVARIANT(winner->is_open_branching());

    if (!winner->sensitivity_performed)
    {
        while (true)
        {
            branching_node* const  left = winner->successor(false).pointer;
            branching_node* const  right = winner->successor(true).pointer;

            if (left != nullptr && left->get_num_stdin_bytes() == winner->get_num_stdin_bytes())
                winner = left;
            else if (right != nullptr && right->get_num_stdin_bytes() == winner->get_num_stdin_bytes())
                winner = right;
            else
                break;
        }
        sensitivity.start(winner, num_driver_executions);
        state = SENSITIVITY;
    }
    else if (!winner->bitshare_performed)
    {
        INVARIANT(!winner->sensitive_stdin_bits.empty());
        bitshare.start(winner, num_driver_executions);
        state = BITSHARE;
    }
    else if (!winner->xor_like_branching_function &&
        typed_minimization_analysis::are_types_of_sensitive_bits_available(winner->best_stdin, winner->sensitive_stdin_bits))
    {
        INVARIANT(!winner->sensitive_stdin_bits.empty() && !winner->minimization_performed);
        typed_minimization.start(winner, winner->best_stdin, num_driver_executions);
        state = TYPED_MINIMIZATION;
    }
    else
    {
        INVARIANT(!winner->sensitive_stdin_bits.empty() && !winner->minimization_performed);
        minimization.start(winner, winner->best_stdin, num_driver_executions);
        state = MINIMIZATION;
    }
}


void  fuzzer::remove_leaf_branching_node(branching_node*  node)
{
    TMPROF_BLOCK();

    INVARIANT(sensitivity.is_ready() || sensitivity.get_node() != node);
    INVARIANT(typed_minimization.is_ready() || typed_minimization.get_node() != node);
    INVARIANT(minimization.is_ready() || minimization.get_node() != node);
    INVARIANT(bitshare.is_ready() || bitshare.get_node() != node);

    if (leaf_branchings.erase(node) != 0)
        ++statistics.leaf_nodes_destroyed;

    while (node->successors.front().pointer == nullptr && node->successors.back().pointer == nullptr)
    {
        if (leaf_branchings.count(node) != 0)
            break;

        branching_node::successor_pointer::LABEL const  label = std::max(node->successor(false).label, node->successor(true).label);

        branching_node* const  pred = node->predecessor;

        INVARIANT(sensitivity.is_ready() || sensitivity.get_node() != node);
        INVARIANT(typed_minimization.is_ready() || typed_minimization.get_node() != node);
        INVARIANT(minimization.is_ready() || minimization.get_node() != node);
        INVARIANT(bitshare.is_ready() || bitshare.get_node() != node);

        primary_coverage_targets.erase(node);
        coverage_failures_with_hope.erase(node);

        delete node;

        ++statistics.nodes_destroyed;

        if (pred == nullptr)
        {
            INVARIANT(node == entry_branching);
            entry_branching = nullptr;
            break;
        }

        pred->set_successor(pred->successor_direction(node), { label, nullptr});

        node = pred;
    }
}


bool  fuzzer::apply_coverage_failures_with_hope()
{
    for (branching_node*  node : coverage_failures_with_hope)
    {
        INVARIANT(node->minimization_performed);

        if (node->minimization_start_execution < node->best_value_execution)
        {
            node->sensitivity_performed = false;
            node->minimization_performed = false;
            node->bitshare_performed = false;
            node->sensitivity_start_execution = std::numeric_limits<natural_32_bit>::max();
            node->minimization_start_execution = std::numeric_limits<natural_32_bit>::max();
            node->bitshare_start_execution = std::numeric_limits<natural_32_bit>::max();
            node->closed = false;
            ++node->num_coverage_failure_resets;

            primary_coverage_targets.process_potential_coverage_target(node);

            ++statistics.coverage_failure_resets;
        }
    }
    coverage_failures_with_hope.clear();
    return !primary_coverage_targets.empty();
 }


}
