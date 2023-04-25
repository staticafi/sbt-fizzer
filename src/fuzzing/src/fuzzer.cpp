#include <fuzzing/fuzzer.hpp>
#include <fuzzing/dump_tree.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>
#include <connection/kleeient_connector.hpp>

namespace  fuzzing {


bool  fuzzer::iid_frontier_record::operator<(iid_frontier_record const&  other) const
{
    if (std::fabs(iid_node->best_coverage_value) < std::fabs(other.iid_node->best_coverage_value))
        return true;
    if (std::fabs(iid_node->best_coverage_value) > std::fabs(other.iid_node->best_coverage_value))
        return false;

    // if (iid_node->sensitivity_performed != other.iid_node->sensitivity_performed)
    //     return iid_node->sensitivity_performed;

    // if (iid_node->trace_index < other.iid_node->trace_index)
    //     return true;
    // if (iid_node->trace_index > other.iid_node->trace_index)
    //     return false;

    if (iid_node->trace_index > other.iid_node->trace_index)
        return true;
    if (iid_node->trace_index < other.iid_node->trace_index)
        return false;

    return distance < other.distance;
}


fuzzer::fuzzer(termination_info const&  info,
               std::unique_ptr<connection::kleeient_connector> kleeient_connector,
               bool const  debug_mode_,
               bool capture_analysis_stats_ )
    : termination_props{ info }

    , num_driver_executions{ 0U }
    , time_point_start{ std::chrono::steady_clock::now() }
    , time_point_current{ time_point_start }

    , entry_branching{}
    , leaf_branchings{}

    , covered_branchings{}
    , uncovered_branchings{}
    , branchings_to_crashes{}

    , did_branchings{}
    , iid_regions{}
    , iid_frontier_sources{}
    , iid_frontier{}

    , state{ STARTUP }
    , sensitivity{}
    , minimization{}
    , bitshare{}
    , jetklee{ std::move(kleeient_connector) }

    , statistics{}
    , analysis_statistics{}

    , capture_analysis_stats{ capture_analysis_stats_ }
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
        remove_leaf_branching_node(leaf_branchings.begin()->first);
}


void  fuzzer::stop_all_analyzes()
{
    sensitivity.stop();
    minimization.stop();
    bitshare.stop();
}


bool  fuzzer::round_begin(TERMINATION_REASON&  termination_reason)
{
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
        if (!can_make_progress())
        {
            stop_all_analyzes();
            debug_save_branching_tree("final");
            terminate();
            termination_reason = TERMINATION_REASON::FUZZING_STRATEGY_DEPLETED;
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

    iomodels::iomanager::instance().clear_stdin();
    iomodels::iomanager::instance().clear_stdout();

    vecb  stdin_bits;
    generate_next_input(stdin_bits);
    vecu8 stdin_bytes;
    bits_to_bytes(stdin_bits, stdin_bytes);
    iomodels::iomanager::instance().get_stdin()->set_bytes(stdin_bytes);

    return true;
}


bool  fuzzer::round_end(execution_record&  record)
{
    execution_record::execution_flags const  flags = process_execution_results();

    bool const  is_path_worth_recording =
            flags & (execution_record::BRANCH_DISCOVERED | execution_record::BRANCH_COVERED | execution_record::EXECUTION_CRASHES);

    if (is_path_worth_recording)
    {
        record.flags = flags;
        record.stdin_bytes = iomodels::iomanager::instance().get_stdin()->get_bytes();
        record.stdin_byte_counts = iomodels::iomanager::instance().get_stdin()->get_counts();
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

    for (int i = 0; i != 3; ++i)
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

            case JETKLEE_QUERY:
                if (jetklee.generate_next_input(stdin_bits))
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
                return;

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

    vecb stdin_bits;
    bytes_to_bits(iomodels::iomanager::instance().get_stdin()->get_bytes(), stdin_bits);
    stdin_bits_pointer const  bits = std::make_shared<vecb>(stdin_bits);
    execution_trace_pointer const  trace = std::make_shared<execution_trace>(iomodels::iomanager::instance().get_trace());
    br_instr_execution_trace_pointer const  br_instr_trace = std::make_shared<br_instr_execution_trace>(iomodels::iomanager::instance().get_br_instr_trace());

    leaf_branching_construction_props  construction_props;

    if (entry_branching == nullptr)
    {
        entry_branching = new branching_node(
                trace->front().id,
                0,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                std::numeric_limits<branching_function_value_type>::max(),
                std::numeric_limits<branching_function_value_type>::max()
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
        if (construction_props.leaf->best_stdin == nullptr || construction_props.leaf->best_summary_value > summary_value)
        {
            construction_props.leaf->best_stdin = bits;
            construction_props.leaf->best_trace = trace;
            construction_props.leaf->best_br_instr_trace = br_instr_trace;
            construction_props.leaf->best_coverage_value = info.value;
            construction_props.leaf->best_summary_value = summary_value;
        }

        if (construction_props.frontier_node == nullptr
                && (!construction_props.leaf->is_direction_explored(false) || !construction_props.leaf->is_direction_explored(true)))
            construction_props.frontier_node = construction_props.leaf;

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
                    construction_props.leaf,
                    bits,
                    trace,
                    br_instr_trace,
                    succ_info.value,
                    succ_info.value * succ_info.value
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
            iomodels::iomanager::instance().get_termination() == iomodels::iomanager::NORMAL ?
                branching_node::successor_pointer::END_NORMAL :
                branching_node::successor_pointer::END_EXCEPTIONAL,
            construction_props.leaf->successor(trace->back().direction).label
            ),
        nullptr
    });

    if (construction_props.diverging_node != nullptr)
    {
        auto const  it_and_state = leaf_branchings.insert({
                construction_props.leaf,
                { construction_props.uncovered_locations, construction_props.frontier_node }
                });
        INVARIANT(it_and_state.second);

        ++statistics.leaf_nodes_created;
        statistics.max_leaf_nodes = std::max(statistics.max_leaf_nodes, leaf_branchings.size());
        statistics.longest_branch = std::max(statistics.longest_branch, (std::size_t)(trace_index + 1));
    }

    switch (state)
    {
        case STARTUP:
            INVARIANT(sensitivity.is_ready() && minimization.is_ready() && bitshare.is_ready() && jetklee.is_ready());
            break;

        case SENSITIVITY:
            INVARIANT(sensitivity.is_busy() && minimization.is_ready() && bitshare.is_ready() && jetklee.is_ready());
            sensitivity.process_execution_results(trace, entry_branching);
            break;

        case MINIMIZATION:
            INVARIANT(sensitivity.is_ready() && minimization.is_busy() && bitshare.is_ready() && jetklee.is_ready());
            minimization.process_execution_results(trace);
            if (minimization.get_node()->is_direction_explored(false) && minimization.get_node()->is_direction_explored(true))
            {
                minimization.stop();
                bitshare.bits_available_for_branching(minimization.get_node(), trace, bits);
            }
            break;

        case BITSHARE:
            INVARIANT(sensitivity.is_ready() && minimization.is_ready() && bitshare.is_busy());
            bitshare.process_execution_results(trace);
            if (bitshare.get_node()->is_direction_explored(false) && bitshare.get_node()->is_direction_explored(true))
                bitshare.stop();
            break;

        case JETKLEE_QUERY:
            INVARIANT(sensitivity.is_ready() && minimization.is_ready() && jetklee.is_busy());
            jetklee.process_execution_results(trace);
            if (jetklee.get_node()->is_direction_explored(false) && jetklee.get_node()->is_direction_explored(true)) {
                jetklee.stop();
                if (capture_analysis_stats)
                    analysis_statistics.stop_jetklee();
            }
            break;

        default: UNREACHABLE(); break;
    }

    execution_record::execution_flags  exe_flags;
    {
        exe_flags = 0;

        if (iomodels::iomanager::instance().get_termination() == iomodels::iomanager::CRASH)
        {
            ++statistics.traces_to_crash;

            auto const  it_and_state = branchings_to_crashes.insert(construction_props.leaf->id);
            if (it_and_state.second)
                exe_flags |= execution_record::EXECUTION_CRASHES;
        }

        if (iomodels::iomanager::instance().get_termination() == iomodels::iomanager::BOUNDARY_CONDITION_VIOLATION)
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

    INVARIANT(sensitivity.is_ready() && minimization.is_ready() && jetklee.is_ready() && state != FINISHED);

    if (state == SENSITIVITY)
    {
        INVARIANT(sensitivity.get_leaf_branching() != nullptr && leaf_branchings.contains(sensitivity.get_leaf_branching()));

        std::unordered_set<branching_node*>  iid_nodes;
        for (branching_node* node = sensitivity.get_leaf_branching(); node != nullptr; node = node->predecessor)
        {
            INVARIANT(node->sensitivity_performed);
            if (!did_branchings.contains(node->id))
            {
                if (node->sensitive_stdin_bits.empty())
                    iid_nodes.insert(node);
                else
                {
                    did_branchings.insert(node->id);
                    iid_regions.erase(node->id);
                }
            }
        }
        for (branching_node* iid_node : iid_nodes)
            if (!did_branchings.contains(iid_node->id) && !covered_branchings.contains(iid_node->id))
            {
                INVARIANT(iid_node->sensitivity_performed && iid_node->sensitive_stdin_bits.empty());

                auto&  region = iid_regions[iid_node->id];
                for (branching_node* node = iid_node->predecessor;
                        node != nullptr && did_branchings.contains(node->id);
                        node = node->predecessor
                        )
                {
                    auto const  it = region.find(node->id);
                    if (it == region.end())
                        region.insert({ node->id, iid_node->trace_index - node->trace_index });
                    else if (it->second < iid_node->trace_index - node->trace_index)
                        it->second = iid_node->trace_index - node->trace_index;
                }
            }
    }

    std::vector<branching_node*> leaves_to_remove;
    for (auto& leaf_and_props : leaf_branchings)
        if (leaf_and_props.first->successor(false).pointer != nullptr || leaf_and_props.first->successor(true).pointer != nullptr)
            leaves_to_remove.push_back(leaf_and_props.first);
    for (branching_node*  leaf : leaves_to_remove)
        remove_leaf_branching_node(leaf);

    for (auto& leaf_and_props : leaf_branchings)
    {
        leaf_branching_processing_props&  props = leaf_and_props.second;
        for (auto  it_loc = props.uncovered_branchings.begin(); it_loc != props.uncovered_branchings.end(); )
        {
            for (auto  it_node = it_loc->second.begin(); it_node != it_loc->second.end(); )
                if (iid_regions.contains((*it_node)->id))
                {
                    if (!iid_frontier_sources.contains(*it_node))
                    {
                        iid_frontier_sources.insert(*it_node);
                        iid_frontier.insert({ *it_node, *it_node, 0U, false });
                    }
                    it_node = it_loc->second.erase(it_node);
                }
                else if ((*it_node)->is_iid_branching() || (*it_node)->minimization_performed || covered_branchings.contains((*it_node)->id))
                    it_node = it_loc->second.erase(it_node);
                else
                    ++it_node;
            if (it_loc->second.empty())
                it_loc = props.uncovered_branchings.erase(it_loc);
            else
                ++it_loc;
        }

        std::vector<branching_node*>  path;
        while (props.frontier_branching != nullptr && (
                    props.frontier_branching->minimization_performed ||
                    props.frontier_branching->is_iid_branching() ||
                    iid_regions.contains(props.frontier_branching->id) ||
                    (props.frontier_branching->is_direction_explored(false) && props.frontier_branching->is_direction_explored(true))
                    ))
        {
            if (path.empty())
            {
                path.push_back(nullptr);
                for (branching_node*  node = leaf_and_props.first; node != props.frontier_branching; node = node->predecessor)
                    path.push_back(node);
            }
            props.frontier_branching = path.back();
            path.pop_back();
        }
    }

    while (!iid_frontier.empty())
    {
        iid_frontier_record const  rec = *iid_frontier.begin();

        if (covered_branchings.contains(rec.iid_node->id) || did_branchings.contains(rec.iid_node->id))
        {
            iid_frontier.erase(iid_frontier.begin());
            iid_regions.erase(rec.iid_node->id);
            continue;
        }

        if (rec.forward)
        {
            auto const  it_region = iid_regions.find(rec.iid_node->id);
            INVARIANT(it_region != iid_regions.end());
            auto const  it = it_region->second.find(rec.node->id);
            if (it == it_region->second.end() || rec.distance > 2U * it->second || iid_regions.contains(rec.node->id))
            {
                iid_frontier.erase(iid_frontier.begin());
                continue;
            }

            if (!rec.node->is_direction_explored(false) || !rec.node->is_direction_explored(true))
                if (!rec.node->sensitivity_performed || (!rec.node->minimization_performed && !rec.node->sensitive_stdin_bits.empty()))
                    break;

            iid_frontier.erase(iid_frontier.begin());
            if (rec.node->successor(false).pointer != nullptr)
                iid_frontier.insert({
                    rec.iid_node,
                    rec.node->successor(false).pointer,
                    rec.distance + 1U,
                    true
                    });
            if (rec.node->successor(true).pointer != nullptr)
                iid_frontier.insert({
                    rec.iid_node,
                    rec.node->successor(true).pointer,
                    rec.distance + 1U,
                    true
                    });
        }
        else
        {
            if (rec.iid_node != rec.node) 
                if (!rec.node->is_direction_explored(false) || !rec.node->is_direction_explored(true))
                    if (!rec.node->sensitivity_performed || (!rec.node->minimization_performed && !rec.node->sensitive_stdin_bits.empty()))
                        break;

            iid_frontier.erase(iid_frontier.begin());
            if (rec.node->predecessor != nullptr && !iid_regions.contains(rec.node->predecessor->id))
                iid_frontier.insert({
                    rec.iid_node,
                    rec.node->predecessor,
                    rec.distance + 1U,
                    false
                    });
            if (rec.iid_node == rec.node)
            {
                if (rec.node->successor(false).pointer != nullptr)
                    iid_frontier.insert({
                        rec.iid_node,
                        rec.node->successor(false).pointer,
                        rec.distance + 1U,
                        true
                        });
                if (rec.node->successor(true).pointer != nullptr)
                    iid_frontier.insert({
                        rec.iid_node,
                        rec.node->successor(true).pointer,
                        rec.distance + 1U,
                        true
                        });
            }
            else
            {
                branching_node*  iid_succ = rec.iid_node;
                while (iid_succ->predecessor != rec.node)
                    iid_succ = iid_succ->predecessor;
                bool const  iid_direction = rec.node->successor_direction(iid_succ);
                if (rec.node->successor(!iid_direction).pointer != nullptr)
                    iid_frontier.insert({
                        rec.iid_node,
                        rec.node->successor(!iid_direction).pointer,
                        rec.distance + 1U,
                        true
                        });
            }
        }
    }
}


void  fuzzer::remove_leaf_branching_node(branching_node*  node)
{
    TMPROF_BLOCK();

    INVARIANT(sensitivity.is_ready() || sensitivity.get_leaf_branching() != node);
    INVARIANT(minimization.is_ready() || minimization.get_node() != node);

    if (leaf_branchings.erase(node) != 0)
        ++statistics.leaf_nodes_destroyed;

    while (node->successors.front().pointer == nullptr && node->successors.back().pointer == nullptr)
    {
        if (leaf_branchings.count(node) != 0)
            break;

        branching_node::successor_pointer::LABEL const  label = std::max(node->successor(false).label, node->successor(true).label);

        branching_node* const  pred = node->predecessor;

        INVARIANT(sensitivity.is_ready() || sensitivity.get_leaf_branching() != node);
        INVARIANT(minimization.is_ready() || minimization.get_node() != node);

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


void  fuzzer::select_next_state()
{
    TMPROF_BLOCK();

    INVARIANT(sensitivity.is_ready() && minimization.is_ready() && jetklee.is_ready() && state != FINISHED);

    struct  selection_winner
    {
        branching_node* node = nullptr;
        branching_node* leaf = nullptr;
    };

    selection_winner winner{};

    {
        struct  did_compare_record : public selection_winner
        {
            std::size_t  num_nodes = 0;

            bool operator<(did_compare_record const&  other) const
            {
                if (node == nullptr || other.node == nullptr)
                    return node != nullptr;

                if (node->sensitivity_performed)
                {
                    if (!other.node->sensitivity_performed)
                        return true;
                }
                else
                {
                    if (other.node->sensitivity_performed)
                        return false;

                    if (num_nodes < other.num_nodes)
                        return false;
                    if (num_nodes > other.num_nodes)
                        return true;
                }

                if (node->trace_index < other.node->trace_index)
                    return true;
                if (node->trace_index > other.node->trace_index)
                    return false;

                if (node->sensitive_stdin_bits.size() < other.node->sensitive_stdin_bits.size())
                    return true;

                return false;
            }
        };

        did_compare_record  did_winner{ winner, 0 };
        for (auto& leaf_and_props : leaf_branchings)
            for (auto& loc_and_nodes : leaf_and_props.second.uncovered_branchings)
                for (branching_node* node : loc_and_nodes.second)
                {
                    did_compare_record const  current {
                            { node, leaf_and_props.first },
                            leaf_and_props.second.uncovered_branchings.size()
                            };
                    if (current < did_winner)
                        did_winner = current;
                }
        winner = did_winner;
    }

    if (winner.node == nullptr)
    {
        INVARIANT(winner.leaf == nullptr);

        if (!iid_frontier.empty())
        {
            debug_save_branching_tree("iid");

            winner.node = iid_frontier.begin()->node;
            if (!winner.node->sensitivity_performed)
            {
                winner.leaf = winner.node;
                while (!leaf_branchings.contains(winner.leaf))
                {
                    branching_node* const  left = winner.leaf->successor(false).pointer;
                    branching_node* const  right = winner.leaf->successor(true).pointer;

                    INVARIANT(left != nullptr || right != nullptr);

                    if (left != nullptr)
                        winner.leaf = left;
                    else
                        winner.leaf = right;
                }
            }
        }
        else
        {
            debug_save_branching_tree("frontier");

            for (auto& leaf_and_props : leaf_branchings)
            {
                branching_node* const  node = leaf_and_props.second.frontier_branching;
                if (node != nullptr && (winner.node == nullptr || winner.node->trace_index > node->trace_index))
                {
                    winner.node = node;
                    winner.leaf = leaf_and_props.first;
                }
            }
        }
    }

    if (winner.node == nullptr)
    {
        state = FINISHED;
        return;
    }

    if (!winner.node->sensitivity_performed)
    {
        INVARIANT(winner.leaf != nullptr && !winner.leaf->sensitivity_performed);
        sensitivity.start(winner.leaf->best_stdin, winner.leaf->best_trace, winner.leaf);
        state = SENSITIVITY;
        return;
    }
    else if (!winner.node->bitshare_performed)
    {
        INVARIANT(!winner.node->sensitive_stdin_bits.empty());
        bitshare.start(winner.node);
        state = BITSHARE;
    }
    else if (jetklee.is_worth_processing(winner_node))
    {
        INVARIANT(!winner_node->jetklee_queued);
        jetklee.start(winner_node);
        state = JETKLEE_QUERY;
    }
    else
    {
        INVARIANT(!winner.node->sensitive_stdin_bits.empty() && !winner.node->minimization_performed);
        minimization.start(winner.node, winner.node->best_stdin);
        state = MINIMIZATION;
    }
}


}
