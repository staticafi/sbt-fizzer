#include <fuzzing/fuzzer.hpp>
#include <fuzzing/dump_tree.hpp>
#include <fuzzing/progress_recorder.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>
#include <map>

namespace  fuzzing {


fuzzer::primary_coverage_target_branchings::primary_coverage_target_branchings(
        std::function<bool(location_id)> const&  is_covered_,
        std::function<std::pair<bool, bool>(branching_node*)> const&  is_iid_
        )
    : loop_heads{}
    , sensitive{}
    , untouched{}
    , iid_twins{}
    , is_covered{ is_covered_ }
    , is_iid{ is_iid_ }
{}


void  fuzzer::primary_coverage_target_branchings::collect_loop_heads_along_path_to_node(branching_node* const  end_node)
{
    std::unordered_map<natural_32_bit, std::pair<bool, branching_node*> >  input_class_coverage;
    {
        for (natural_32_bit  input_width : get_input_width_classes())
            input_class_coverage.insert({ input_width, { false, nullptr } });

        std::unordered_map<location_id, std::unordered_set<location_id> >  loop_heads_to_bodies;
        {
            std::vector<loop_exit_and_direct_successor>  loop_exits;
            detect_loops_along_path_to_node(end_node, loop_exits, loop_heads_to_bodies);
        }

        for (branching_node*  node = end_node; node != nullptr; node = node->predecessor)
            if (loop_heads_to_bodies.contains(node->get_location_id()))
            {
                natural_32_bit const  input_class = get_input_width_class(node->get_num_stdin_bytes());
                auto&  state_and_node = input_class_coverage.at(input_class);
                if (!state_and_node.first)
                {
                    if (node->is_open_branching())
                    {
                        if (state_and_node.second == nullptr || node->get_num_stdin_bytes() < state_and_node.second->get_num_stdin_bytes())
                            state_and_node.second = node;
                    }
                    else
                        state_and_node.first = true;
                }
            }
    }

    for (auto const&  width_and_state_and_node : input_class_coverage)
        if (!width_and_state_and_node.second.first && width_and_state_and_node.second.second != nullptr)
            loop_heads.insert(width_and_state_and_node.second.second);
}


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
            auto const  iid_and_useful = is_iid(node);
            if (iid_and_useful.first)
            {
                if (iid_and_useful.second)
                    iid_twins.insert(node);
            }
            else
                untouched.insert(node);
        }
    }
}


void  fuzzer::primary_coverage_target_branchings::erase(branching_node* const  node)
{
    ASSUMPTION(node != nullptr);
    loop_heads.erase(node);
    sensitive.erase(node);
    untouched.erase(node);
    iid_twins.erase(node);
}


bool  fuzzer::primary_coverage_target_branchings::empty() const
{
    return loop_heads.empty() && sensitive.empty() && untouched.empty() && iid_twins.empty();
}


void  fuzzer::primary_coverage_target_branchings::clear()
{
    loop_heads.clear();
    sensitive.clear();
    untouched.clear();
    iid_twins.clear();
}


void  fuzzer::primary_coverage_target_branchings::do_cleanup()
{
    for (auto  it = loop_heads.begin(); it != loop_heads.end(); )
        if ((*it)->is_open_branching())
            ++it;
        else
            it = loop_heads.erase(it);

    std::unordered_set<branching_node*>  work_set{ sensitive.begin(), sensitive.end() };
    work_set.insert(untouched.begin(), untouched.end());
    work_set.insert(iid_twins.begin(), iid_twins.end());
    sensitive.clear();
    untouched.clear();
    iid_twins.clear();
    while (!work_set.empty())
    {
        branching_node* const  node = *work_set.begin();
        work_set.erase(work_set.begin());
        process_potential_coverage_target(node);
    }
}


branching_node*  fuzzer::primary_coverage_target_branchings::get_best(natural_32_bit const  max_input_width)
{
    TMPROF_BLOCK();

    branching_node*  best_node = nullptr;

    if (!loop_heads.empty())
    {
        best_node = *loop_heads.begin();
        recorder().on_strategy_turn_primary_loop_head();
        return best_node;
    }

    best_node = get_best(sensitive, max_input_width);
    if (best_node != nullptr)
    {
        recorder().on_strategy_turn_primary_sensitive();
        return best_node;
    }

    best_node = get_best(untouched, max_input_width);
    if (best_node != nullptr)
    {
        recorder().on_strategy_turn_primary_untouched();
        return best_node;
    }

    best_node = get_best(iid_twins, max_input_width);
    if (best_node != nullptr)
    {
        recorder().on_strategy_turn_primary_iid_twins();
        return best_node;
    }

    return nullptr;
}


branching_node*  fuzzer::primary_coverage_target_branchings::get_best(
        std::unordered_set<branching_node*> const&  targets,
        natural_32_bit const  max_input_width
        )
{
    struct  branching_node_with_less_than
    {
        branching_node_with_less_than(branching_node* const  node_, natural_32_bit const  max_input_width)
            : node{ node_ }
            , distance_to_central_input_width_class{
                    std::abs((integer_32_bit)get_input_width_class(max_input_width / 2U) -
                             (integer_32_bit)get_input_width_class(node->get_num_stdin_bytes()))
                    }
        {}
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
            if (distance_to_central_input_width_class < other.distance_to_central_input_width_class)
                return true;
            if (distance_to_central_input_width_class > other.distance_to_central_input_width_class)
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
        integer_32_bit  distance_to_central_input_width_class;
    };
    if (!targets.empty())
    {
        branching_node_with_less_than  best{ *targets.begin(), max_input_width };
        for (auto  it = std::next(targets.begin()); it != targets.end(); ++it)
        {
            branching_node_with_less_than const  current{ *it, max_input_width };
            if (current < best)
                best = current;
        }
        return best;
    }
    return nullptr;
}


fuzzer::probability_generator_all_then_all::probability_generator_all_then_all(
        float_32_bit const  false_direction_probability_,
        natural_32_bit const  total_num_samples_,
        bool const  first_direction_
        )
    : samples_total{
            (natural_32_bit)(false_direction_probability_ * (float_32_bit)total_num_samples_ + 0.5f),
            total_num_samples_ - samples_total[0]
            }
    , samples_consumed{ 0U, 0U }
    , direction{ first_direction_}
{
    ASSUMPTION(false_direction_probability_ >= 0.0f && false_direction_probability_ <= 1.0f && total_num_samples_ >= 1U);
    INVARIANT(samples_total[0] > 0 || samples_total[1] > 0);
}


float_32_bit  fuzzer::probability_generator_all_then_all::next()
{
    while (true)
    {
        int const  index = direction ? 1 : 0;
        if (samples_consumed[index] < samples_total[index])
        {
            ++samples_consumed[index];
            return direction ? 1.0f : 0.0f;
        }
        samples_consumed[index] = 0U;
        direction = !direction;
    }
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

    recorder().on_post_node_closed(node);

    if (node->predecessor != nullptr)
        update_close_flags_from(node->predecessor);
}


std::vector<natural_32_bit> const&  fuzzer::get_input_width_classes()
{
    static std::vector<natural_32_bit> const  input_width_classes{ 1, 2, 4, 8, 16, 32, 64, 128, 256, 1024 };
    return input_width_classes;
}


std::unordered_set<natural_32_bit> const&  fuzzer::get_input_width_classes_set()
{
    static std::unordered_set<natural_32_bit> const  input_width_classes_set{ get_input_width_classes().begin(), get_input_width_classes().end() };
    return input_width_classes_set;
}


natural_32_bit  fuzzer::get_input_width_class(natural_32_bit const  num_input_bytes)
{
    return get_input_width_classes().at(get_input_width_class_index(num_input_bytes));
}


natural_32_bit  fuzzer::get_input_width_class_index(natural_32_bit const  num_input_bytes)
{
    return (natural_32_bit)std::distance(
            get_input_width_classes().begin(),
            std::lower_bound(
                    get_input_width_classes().begin(),
                    get_input_width_classes().end(),
                    num_input_bytes
                    )
            );
}


void  fuzzer::detect_loops_along_path_to_node(
        branching_node* const  end_node,
        std::vector<loop_exit_and_direct_successor>&  loop_exits,
        std::unordered_map<location_id, std::unordered_set<location_id> >&  loop_heads_to_bodies
        )
{
    std::vector<loop_exit_and_direct_successor>  branching_stack;
    std::unordered_map<location_id, natural_32_bit>  pointers_to_branching_stack;

    // We must explore the 'branching_records' backwards,
    // because of do-while loops (all loops terminate with
    // the loop-head condition, but do not have to start
    // with it).
    for (branching_node*  node = end_node, *succ_node = node; node != nullptr; succ_node = node, node = node->predecessor)
    {
        auto const  it = pointers_to_branching_stack.find(node->get_location_id());
        if (it == pointers_to_branching_stack.end())
        {
            pointers_to_branching_stack.insert({ node->get_location_id(), (natural_32_bit)branching_stack.size() });
            branching_stack.push_back({ node, succ_node });
        }
        else
        {
            loop_exit_and_direct_successor const&  props = branching_stack.at(it->second);
            if (loop_exits.empty() || loop_exits.back().loop_exit != props.loop_exit)
                loop_exits.push_back(props);

            auto&  loop_body = loop_heads_to_bodies[props.loop_exit->get_location_id()];
            for (std::size_t  end_size = it->second + 1ULL; branching_stack.size() > end_size; )
            {
                loop_body.insert(branching_stack.back().loop_exit->get_location_id());
                pointers_to_branching_stack.erase(branching_stack.back().loop_exit->get_location_id());
                branching_stack.pop_back();
            }
        }
    }
    std::reverse(loop_exits.begin(), loop_exits.end());
}


void  fuzzer::detect_loop_entries(
        std::vector<loop_exit_and_direct_successor> const&  loop_exits,
        std::unordered_map<location_id, std::unordered_set<location_id> > const&  loop_heads_to_bodies,
        std::vector<branching_node*>&  loop_entries
        )
{
    for (std::size_t  i = 0U; i != loop_exits.size(); ++i)
    {
        branching_node* const  stop_node = i == 0 ? nullptr : loop_exits.at(i - 1).loop_exit;
        branching_node* const  loop_exit = loop_exits.at(i).loop_exit;
        branching_node*        loop_entry = loop_exit;
        while (loop_entry->predecessor != stop_node &&
                    (loop_entry->predecessor->get_location_id() == loop_exit->get_location_id() ||
                            loop_heads_to_bodies.at(loop_exit->get_location_id()).contains(loop_entry->predecessor->get_location_id())))
            loop_entry = loop_entry->predecessor;
        loop_entries.push_back(loop_entry);
    }
}


void  fuzzer::compute_pure_loop_bodies(
            std::unordered_map<location_id, std::unordered_set<location_id> > const&  loop_heads_to_bodies,
            std::unordered_set<location_id>&  pure_loop_bodies
            )
{
    for (auto const&  loc_and_bodies : loop_heads_to_bodies)
        pure_loop_bodies.insert(loc_and_bodies.second.begin(), loc_and_bodies.second.end());
    for (auto const&  loc_and_bodies : loop_heads_to_bodies)
        pure_loop_bodies.erase(loc_and_bodies.first);
}


std::unordered_map<branching_node*, fuzzer::iid_pivot_props>::const_iterator  fuzzer::select_best_iid_pivot(
        std::unordered_map<branching_node*, iid_pivot_props> const&  pivots,
        natural_32_bit const  max_input_width,
        random_generator_for_natural_32_bit&  random_generator,
        float_32_bit const  LIMIT_STEP
        )
{
    struct  iid_pivot_with_less_than
    {
        iid_pivot_with_less_than(branching_node* const  pivot_, natural_32_bit const  max_input_width)
            : pivot{ pivot_ }
            , abs_value{ std::fabs(pivot->best_coverage_value) }
            , distance_to_central_input_width_class{
                    std::abs((integer_32_bit)get_input_width_class(max_input_width / 2U) -
                             (integer_32_bit)get_input_width_class(pivot->get_num_stdin_bytes()))
                    }
        {}
        operator branching_node*() const { return pivot; }
        bool  operator<(iid_pivot_with_less_than const&  other) const
        {
            if (abs_value < other.abs_value)
                return true;
            if (abs_value > other.abs_value)
                return false;

            if (distance_to_central_input_width_class < other.distance_to_central_input_width_class)
                return true;
            if (distance_to_central_input_width_class > other.distance_to_central_input_width_class)
                return false;

            if (pivot->get_num_stdin_bytes() < other.pivot->get_num_stdin_bytes())
                return true;
            if (pivot->get_num_stdin_bytes() > other.pivot->get_num_stdin_bytes())
                return false;

            return pivot->get_trace_index() < other.pivot->get_trace_index();
        }
        branching_node*  pivot;
        branching_function_value_type  abs_value;
        integer_32_bit  distance_to_central_input_width_class;
    };
    std::vector<iid_pivot_with_less_than>  pivots_order;
    for (auto const&  pivot_and_props : pivots)
        pivots_order.push_back({ pivot_and_props.first, max_input_width });
    std::sort(pivots_order.begin(), pivots_order.end());

    float_32_bit const  probability{ get_random_float_32_bit_in_range(0.0f, 1.0f, random_generator) };
    std::size_t  i = 0;
    for (float_32_bit  limit = LIMIT_STEP; i + 1U < pivots_order.size() && probability > limit; limit += LIMIT_STEP * (1.0f - limit))
        ++i;

    return pivots.find(pivots_order.at(i));
}


void  fuzzer::compute_hit_counts_histogram(branching_node const* const  pivot, histogram_of_hit_counts_per_direction&  histogram)
{
    ASSUMPTION(pivot != nullptr);
    for (branching_node const*  node = pivot; node->predecessor != nullptr; node = node->predecessor)
        ++histogram[node->predecessor->get_location_id().id][node->predecessor->successor_direction(node)];
}


void  fuzzer::compute_histogram_of_false_direction_probabilities(
        natural_32_bit const  input_width,
        std::unordered_set<location_id> const&  pure_loop_bodies,
        std::unordered_map<branching_node*, iid_pivot_props> const&  pivots,
        histogram_of_false_direction_probabilities&  histogram
        )
{
    std::unordered_map<location_id::id_type, std::multimap<branching_function_value_type, float_32_bit> > hist_pack;
    for (auto  it = pivots.begin(); it != pivots.end(); ++it)
        if (it->first->get_num_stdin_bytes() == input_width)
            for (auto const& id_and_hits : it->second.histogram)
            {
                auto const&  hit_count = id_and_hits.second.hit_count;
                INVARIANT(hit_count[false] != 0U || hit_count[true] != 0U);
                float_64_bit const  false_direction_probability {
                        (float_64_bit)hit_count[false] / ((float_64_bit)hit_count[false] + (float_64_bit)hit_count[true])
                        };
                hist_pack[id_and_hits.first].insert({
                        std::fabs(it->first->best_coverage_value),
                        (float_32_bit)false_direction_probability
                        });
            }
    for (auto const&  id_and_pack : hist_pack)
    {
        auto const&  pack = id_and_pack.second;
        vecf32  probabilities;
        for (auto  it = pack.rbegin(); it != pack.rend(); ++it)
            if (std::fabs(pack.begin()->first - it->first) >= 1e-6f)
            {
                float_32_bit const  t = -it->first / (pack.begin()->first - it->first);
                float_32_bit const  raw_estimate = it->second + t * (pack.begin()->second - it->second);
                float_32_bit const  estimate = std::min(std::max(0.0f, raw_estimate), 1.0f);
                probabilities.push_back(estimate);
            }
        if (probabilities.empty())
        {
            probabilities.push_back(pack.begin()->second);
            if (pure_loop_bodies.contains(id_and_pack.first))
                probabilities.push_back(0.5f);
        }
        histogram[id_and_pack.first] = avg(probabilities);
    }
}


branching_node*  fuzzer::select_start_node_for_monte_carlo_search(
        std::vector<branching_node*> const&  loop_entries,
        std::vector<loop_exit_and_direct_successor> const&  loop_exits,
        random_generator_for_natural_32_bit&  random_generator,
        float_32_bit const  LIMIT_STEP,
        branching_node*  fallback_node
        )
{
    ASSUMPTION(LIMIT_STEP >= 0.0f && LIMIT_STEP <= 1.0f && loop_entries.size() == loop_exits.size());
    if (!loop_entries.empty())
    {
        std::vector<branching_node*>  loop_nodes;
        {
            loop_nodes.reserve(2 * loop_entries.size());
            for (std::size_t  i = 0; i != loop_entries.size(); ++i)
            {
                INVARIANT(loop_entries.at(i)->get_trace_index() < loop_exits.at(i).successor->get_trace_index());
                loop_nodes.push_back(loop_entries.at(i));
                loop_nodes.push_back(loop_exits.at(i).successor);
            }
        }

        float_32_bit const  probability{ get_random_float_32_bit_in_range(0.0f, 1.0f, random_generator) };
        std::size_t  i = 0;
        for (float_32_bit  limit = LIMIT_STEP;
                i != loop_nodes.size() && probability > limit;
                limit += LIMIT_STEP * (1.0f - limit)
                )
            ++i;
        for ( ; i < loop_nodes.size(); ++i)
        {
            branching_node* const  node = loop_nodes.at((loop_nodes.size() - 1U) - i);
            if (!node->is_closed())
                return node;
        }
    }
    return fallback_node;
}


std::shared_ptr<fuzzer::probability_generator_random_uniform>  fuzzer::compute_probability_generators_for_locations(
        histogram_of_false_direction_probabilities const&  probabilities,
        histogram_of_hit_counts_per_direction const&  hit_counts,
        std::unordered_set<location_id> const&  pure_loop_bodies,
        probability_generators_for_locations&  generators,
        random_generator_for_natural_32_bit&  generator_for_generator_selection,
        random_generator_for_natural_32_bit&  generator_for_generators
        )
{
    std::shared_ptr<probability_generator_random_uniform> const  random_uniform_generator{
            std::make_shared<probability_generator_random_uniform>(generator_for_generators)
            };

    for (auto const&  id_and_probability : probabilities)
        if (pure_loop_bodies.contains(id_and_probability.first))
        {
            switch (get_random_integer_32_bit_in_range(0, 2, generator_for_generator_selection))
            {
                case 0:
                    generators[id_and_probability.first] = random_uniform_generator;
                    break;
                case 1:
                    generators[id_and_probability.first] = std::make_shared<probability_generator_all_then_all>(
                            id_and_probability.second,
                            hit_counts.at(id_and_probability.first).total(),
                            false
                            );
                    break;
                case 2:
                    generators[id_and_probability.first] = std::make_shared<probability_generator_all_then_all>(
                            id_and_probability.second,
                            hit_counts.at(id_and_probability.first).total(),
                            true
                            );
                    break;
                default: UNREACHABLE(); break;
            }
        }
        else
            generators[id_and_probability.first] = random_uniform_generator;

    return random_uniform_generator;    
}


branching_node*  fuzzer::monte_carlo_search(
        branching_node* const  start_node,
        histogram_of_false_direction_probabilities const&  histogram,
        probability_generators_for_locations const&  generators,
        probability_generator_random_uniform&  location_miss_generator
        )
{
    TMPROF_BLOCK();

    ASSUMPTION(start_node != nullptr && !start_node->is_closed());

    branching_node*  pivot = start_node;
    while (true)
    {
        branching_node* const  successor{ monte_carlo_step(pivot, histogram, generators, location_miss_generator) };
        if (successor == nullptr)
            break;
        pivot = successor;
    }

    INVARIANT(pivot != nullptr && pivot->is_open_branching());

    return pivot;
}


std::pair<branching_node*, bool>  fuzzer::monte_carlo_backward_search(
        branching_node* const  start_node,
        branching_node* const  end_node,
        histogram_of_false_direction_probabilities const&  histogram,
        probability_generators_for_locations const&  generators,
        probability_generator_random_uniform&  location_miss_generator
        )
{
    TMPROF_BLOCK();

    ASSUMPTION(start_node != nullptr && end_node != nullptr && !end_node->is_closed());

    if (start_node == end_node)
        return { end_node, end_node->is_direction_unexplored(false) ? false : true };

    branching_node*  pivot = start_node;
    while (pivot->predecessor->is_closed())
        pivot = pivot->predecessor;

    while (pivot->predecessor != end_node)
    {
        branching_node* const  successor{ monte_carlo_step(pivot->predecessor, histogram, generators, location_miss_generator) };
        if (successor != pivot)
            break;
        pivot = pivot->predecessor;
    }

    return { pivot->predecessor, !pivot->predecessor->successor_direction(pivot) };
}


branching_node*  fuzzer::monte_carlo_step(
        branching_node* const  pivot,
        histogram_of_false_direction_probabilities const&  histogram,
        probability_generators_for_locations const&  generators,
        probability_generator_random_uniform&  location_miss_generator
        )
{
    INVARIANT(pivot != nullptr && !pivot->is_closed());

    branching_node*  successor = nullptr;

    branching_node*  left = pivot->successor(false).pointer;
    branching_node*  right = pivot->successor(true).pointer;

    bool const  can_go_left = left != nullptr && !left->is_closed();
    bool const  can_go_right = right != nullptr && !right->is_closed();

    bool  desired_direction;
    {
        float_32_bit  false_direction_probability;
        {
            auto const  it = histogram.find(pivot->get_location_id().id);
            false_direction_probability = it != histogram.end() ? it->second : 0.5f;
        }
        float_32_bit  probability;
        {
            auto const  it = generators.find(pivot->get_location_id().id);
            probability = it != generators.end() ? it->second->next() : location_miss_generator.next();
        }
        desired_direction = probability <= false_direction_probability ? false : true;
    }

    bool const can_go_desired_direction = (desired_direction == false && can_go_left) || (desired_direction == true && can_go_right);

    if (can_go_desired_direction)
        successor = desired_direction == false ? left : right;
    else if (!pivot->is_open_branching())
        successor = can_go_left ? left : right;

    return successor;
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
            [this](branching_node* const  node) -> std::pair<bool, bool> {
                    auto const  it = iid_pivots.find(node->get_location_id());
                    if (it == iid_pivots.end())
                        return { false, false };
                    for (auto const&  pivot_and_props : it->second.pivots)
                        if (pivot_and_props.first->get_num_stdin_bytes() == node->get_num_stdin_bytes()
                                && std::fabs(pivot_and_props.first->best_coverage_value) <= std::fabs(node->best_coverage_value))
                            return { true, false };
                    return { true, true };
                    }                    
            }
    , iid_pivots{}

    , coverage_failures_with_hope{}

    , state{ STARTUP }
    , sensitivity{}
    , typed_minimization{}
    , minimization{}
    , bitshare{}

    , max_input_width{ 0U }

    , generator_for_iid_location_selection{}
    , generator_for_iid_approach_selection{}
    , generator_for_generator_selection{}

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

    recorder().flush_post_data();

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

        primary_coverage_targets.collect_loop_heads_along_path_to_node(construction_props.leaf);
        for (branching_node*  node = construction_props.leaf; node != construction_props.diverging_node->predecessor; node = node->predecessor)
            primary_coverage_targets.process_potential_coverage_target(node);

        ++statistics.leaf_nodes_created;
        statistics.max_leaf_nodes = std::max(statistics.max_leaf_nodes, leaf_branchings.size());
        statistics.longest_branch = std::max(statistics.longest_branch, (std::size_t)(trace_index + 1));
    }
    else
        update_close_flags_from(construction_props.leaf);

    if (max_input_width < construction_props.leaf->get_num_stdin_bytes())
    {
        max_input_width = construction_props.leaf->get_num_stdin_bytes();

        statistics.max_input_width = max_input_width;
    }

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
                {
                    auto const  it_and_state = iid_pivots[node->get_location_id()].pivots.insert({ node, {} });
                    iid_pivot_props&  props = it_and_state.first->second;
                    detect_loops_along_path_to_node(node, props.loop_exits, props.loop_heads_to_bodies);
                    detect_loop_entries(props.loop_exits, props.loop_heads_to_bodies, props.loop_entries);
                    compute_pure_loop_bodies(props.loop_heads_to_bodies, props.pure_loop_bodies);
                    compute_hit_counts_histogram(node, props.histogram);
                }
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

    branching_node*  winner = nullptr;
    if (!entry_branching->is_closed())
    {
        winner = primary_coverage_targets.get_best(max_input_width);
        if (winner == nullptr)
            winner = select_iid_coverage_target();
    }

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

            bool const  can_go_left = left != nullptr && left->get_num_stdin_bytes() == winner->get_num_stdin_bytes();
            bool const  can_go_right = right != nullptr && right->get_num_stdin_bytes() == winner->get_num_stdin_bytes();

            if (can_go_left && can_go_right)
                winner = left->max_successors_trace_index >= right->max_successors_trace_index ? left : right;
            else if (can_go_left)
                winner = left;
            else if (can_go_right)
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


branching_node*  fuzzer::select_iid_coverage_target() const
{
    TMPROF_BLOCK();

    if (iid_pivots.empty() || entry_branching->is_closed())
        return nullptr;

    auto const  it_loc = std::next(
            iid_pivots.begin(),
            get_random_natural_32_bit_in_range(0, iid_pivots.size() - 1, generator_for_iid_location_selection)
            );
    auto const  it_pivot = select_best_iid_pivot(
            it_loc->second.pivots,
            max_input_width,
            it_loc->second.generator_for_pivot_selection,
            0.75f
            );

    histogram_of_false_direction_probabilities  histogram;
    compute_histogram_of_false_direction_probabilities(
            it_pivot->first->get_num_stdin_bytes(),
            it_pivot->second.pure_loop_bodies,
            it_loc->second.pivots,
            histogram
            );

    probability_generators_for_locations  generators;
    auto const  random_uniform_generator = compute_probability_generators_for_locations(
            histogram,
            it_pivot->second.histogram,
            it_pivot->second.pure_loop_bodies,
            generators,
            it_pivot->second.generator_for_monte_carlo,
            generator_for_generator_selection
            );

    branching_node*  winner;
    if (false)  // original code: if (get_random_natural_32_bit_in_range(1, 100, generator_for_iid_approach_selection) <= 50)
                // Currently diabled, because it performs worse for some yet unknown reason.
    {
        auto const  node_and_direction = monte_carlo_backward_search(
                it_pivot->first,
                entry_branching,
                histogram,
                generators,
                *random_uniform_generator
                );
        branching_node* const  successor = node_and_direction.first->successor(node_and_direction.second).pointer;
        if (successor != nullptr)
            winner = monte_carlo_search(successor, histogram, generators, *random_uniform_generator);
        else if (!node_and_direction.first->is_open_branching())
            winner = monte_carlo_search(node_and_direction.first, histogram, generators, *random_uniform_generator);
        else
            winner = node_and_direction.first;

        recorder().on_strategy_turn_monte_carlo_backward();
    }
    else
    {
        branching_node* const  start_node = select_start_node_for_monte_carlo_search(
                it_pivot->second.loop_entries,
                it_pivot->second.loop_exits,
                it_pivot->second.generator_for_start_node_selection,
                0.75f,
                entry_branching
                );

        winner = monte_carlo_search(start_node, histogram, generators, *random_uniform_generator);

        recorder().on_strategy_turn_monte_carlo();
    }
    
    INVARIANT(winner != nullptr);

    return winner;
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
