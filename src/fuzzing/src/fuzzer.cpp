#include <fuzzing/fuzzer.hpp>
#include <fuzzing/progress_recorder.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>
#include <map>

namespace  fuzzing {


fuzzer::primary_coverage_target_branchings::primary_coverage_target_branchings(
        std::function<bool(location_id)> const&  is_covered_,
        std::function<branching_node*(location_id)> const&  iid_pivot_with_lowest_abs_value_,
        performance_statistics* const  statistics_ptr_
        )
    : loop_heads{}
    , sensitive{}
    , untouched{}
    , iid_twins{}
    , is_covered{ is_covered_ }
    , iid_pivot_with_lowest_abs_value{ iid_pivot_with_lowest_abs_value_ }
    , statistics{ statistics_ptr_ }
{}


void  fuzzer::primary_coverage_target_branchings::collect_loop_heads_along_path_to_node(branching_node* const  end_node)
{
    std::unordered_map<natural_32_bit, std::pair<bool, branching_node*> >  input_class_coverage;
    {
        for (natural_32_bit  input_width : get_input_width_classes())
            input_class_coverage.insert({ input_width, { false, nullptr } });

        std::unordered_map<location_id, std::unordered_set<location_id> >  loop_heads_to_bodies;
        detect_loops_along_path_to_node(end_node, loop_heads_to_bodies, nullptr);

        for (branching_node*  node = end_node; node != nullptr; node = node->predecessor)
            if (loop_heads_to_bodies.contains(node->get_location_id()))
            {
                natural_32_bit const  input_class = get_input_width_class(node->get_num_stdin_bytes());
                auto&  state_and_node = input_class_coverage.at(input_class);
                if (!state_and_node.first)
                {
                    if (node->is_open_branching())
                    {
                        struct  local
                        {
                            static bool  less_than(branching_node const* const  left, branching_node const* const  right)
                            {
                                if (left->get_num_stdin_bytes() < right->get_num_stdin_bytes())
                                    return true;
                                if (left->get_num_stdin_bytes() > right->get_num_stdin_bytes())
                                    return false;
                                return left->get_trace_index() < right->get_trace_index();
                            }
                        };
                        if (state_and_node.second == nullptr || local::less_than(node, state_and_node.second))
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


void  fuzzer::primary_coverage_target_branchings::process_potential_coverage_target(
        std::pair<branching_node*, bool> const&  node_and_flag
        )
{
    auto const [node, flag] = node_and_flag;
    ASSUMPTION(node != nullptr);
    if (node->is_open_branching() && !is_covered(node->get_location_id()))
    {
        if (node->sensitivity_performed)
        {
            if (!node->sensitive_stdin_bits.empty() && (!node->bitshare_performed || !node->minimization_performed))
                sensitive.insert(node_and_flag);
        }
        else
        {
            branching_node* const  iid_pivot = iid_pivot_with_lowest_abs_value(node->get_location_id());
            if (iid_pivot != nullptr)
            {
                if (std::fabs(node->best_coverage_value) < std::fabs(iid_pivot->best_coverage_value))
                {
                    auto const  it_and_state = iid_twins.insert({ node->get_location_id(), node_and_flag });
                    if (!it_and_state.second &&
                            std::fabs(node->best_coverage_value) < std::fabs(it_and_state.first->second.first->best_coverage_value))
                        it_and_state.first->second = node_and_flag;
                }
            }
            else
                untouched.insert(node_and_flag);
        }
    }
}


void  fuzzer::primary_coverage_target_branchings::erase(branching_node* const  node)
{
    ASSUMPTION(node != nullptr);
    loop_heads.erase(node);
    sensitive.erase(node);
    untouched.erase(node);
    auto const  it = iid_twins.find(node->get_location_id());
    if (it != iid_twins.end() && it->second.first == node)
        iid_twins.erase(it);
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
    TMPROF_BLOCK();

    for (auto  it = loop_heads.begin(); it != loop_heads.end(); )
        if ((*it)->is_open_branching())
            ++it;
        else
            it = loop_heads.erase(it);

    std::unordered_map<branching_node*, bool>  work_set{ sensitive.begin(), sensitive.end() };
    work_set.insert(untouched.begin(), untouched.end());
    for (auto const&  loc_and_props : iid_twins)
        work_set.insert(loc_and_props.second);
    sensitive.clear();
    untouched.clear();
    iid_twins.clear();
    while (!work_set.empty())
    {
        std::pair<branching_node*, bool> const  node_and_flag = *work_set.begin();
        work_set.erase(work_set.begin());
        process_potential_coverage_target(node_and_flag);
    }
}


branching_node*  fuzzer::primary_coverage_target_branchings::get_best(natural_32_bit const  max_input_width)
{
    TMPROF_BLOCK();

    branching_node*  best_node = nullptr;

    if (!loop_heads.empty())
    {
        best_node = *loop_heads.begin();
        ++statistics->strategy_primary_loop_head;
        recorder().on_strategy_turn_primary_loop_head();
        return best_node;
    }

    best_node = get_best(sensitive, max_input_width);
    if (best_node != nullptr)
    {
        if (!loop_heads.empty())
            return get_best(max_input_width);
        ++statistics->strategy_primary_sensitive;
        recorder().on_strategy_turn_primary_sensitive();
        return best_node;
    }

    best_node = get_best(untouched, max_input_width);
    if (best_node != nullptr)
    {
        if (!loop_heads.empty())
            return get_best(max_input_width);
        ++statistics->strategy_primary_untouched;
        recorder().on_strategy_turn_primary_untouched();
        return best_node;
    }

    if (!iid_twins.empty())
    {
        auto const  it = iid_twins.begin();
        if (!it->second.second) 
        {
            collect_loop_heads_along_path_to_node(it->second.first);
            it->second.second = true;
            if (!loop_heads.empty())
                return get_best(max_input_width);
        }
        ++statistics->strategy_primary_iid_twins;
        recorder().on_strategy_turn_primary_iid_twins();
        return it->second.first;
    }

    return nullptr;
}


branching_node*  fuzzer::primary_coverage_target_branchings::get_best(
        std::unordered_map<branching_node*, bool>&  targets,
        natural_32_bit const  max_input_width
        )
{
    if (targets.empty())
        return nullptr;

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

    branching_node_with_less_than  best{ targets.begin()->first, max_input_width };
    for (auto  it = std::next(targets.begin()); it != targets.end(); ++it)
    {
        branching_node_with_less_than const  current{ it->first, max_input_width };
        if (current < best)
            best = current;
    }

    auto const  it = targets.find(best);
    if (!it->second)
    {
        collect_loop_heads_along_path_to_node(it->first);
        it->second = true;
    }

    return best;
}


void  fuzzer::histogram_of_hit_counts_per_direction::merge(
        histogram_of_hit_counts_per_direction const*  histogram,
        histogram_of_hit_counts_per_direction const* const  end,
        hit_counts_map&  result
        )
{
    for ( ; histogram != end; histogram = histogram->get_predecessor().get())
        result.insert(histogram->hit_counts.begin(), histogram->hit_counts.end());
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
    if (get_input_width_classes().back() <= num_input_bytes)
        return (natural_32_bit)get_input_width_classes().size() - 1U;
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
        std::unordered_map<location_id, std::unordered_set<location_id> >&  loop_heads_to_bodies,
        std::vector<loop_boundary_props>* const  loops
        )
{
    struct  loop_exit_props
    {
        branching_node*  exit;
        branching_node*  successor;
        natural_32_bit  index;
    };

    std::vector<loop_exit_props>  branching_stack;
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
            branching_stack.push_back({ node, succ_node, 0U });
        }
        else
        {
            loop_exit_props&  props = branching_stack.at(it->second);

            if (loops != nullptr)
            {
                if (props.index == 0U)
                {
                    props.index = (natural_32_bit)loops->size();
                    loops->push_back({ node, props.exit, props.successor });
                }
                else
                    loops->at(props.index).entry = node;
            }

            auto&  loop_body = loop_heads_to_bodies[props.exit->get_location_id()];
            for (std::size_t  end_size = it->second + 1ULL; branching_stack.size() > end_size; )
            {
                loop_body.insert(branching_stack.back().exit->get_location_id());
                pointers_to_branching_stack.erase(branching_stack.back().exit->get_location_id());
                branching_stack.pop_back();
            }
        }
    }

    if (loops != nullptr)
        for (loop_boundary_props&  props : *loops)
        {
            auto const&  loop_body = loop_heads_to_bodies.at(props.exit->get_location_id());
            while (props.entry->predecessor != nullptr
                        && (props.entry->predecessor->get_location_id() == props.exit->get_location_id() ||
                            loop_body.contains(props.entry->predecessor->get_location_id())))
                props.entry = props.entry->predecessor;
        }
}


void  fuzzer::compute_loop_boundaries(
            std::vector<loop_boundary_props> const&  loops,
            std::vector<branching_node*>&  loop_boundaries
            )
{
    std::unordered_set<branching_node*>  stored;
    loop_boundaries.reserve(2U * loops.size());
    for (loop_boundary_props const&  props : loops)
    {
        if (!stored.contains(props.entry))
        {
            loop_boundaries.push_back(props.entry);
            stored.insert(props.entry);
        }
        if (!stored.contains(props.successor))
        {
            loop_boundaries.push_back(props.successor);
            stored.insert(props.successor);
        }
    }
    std::sort(
            loop_boundaries.begin(),
            loop_boundaries.end(),
            [](branching_node const* const  left, branching_node const* const  right) {
                    return left->get_trace_index() < right->get_trace_index();
                    }
            );
}


std::unordered_map<branching_node*, fuzzer::iid_pivot_props>::const_iterator  fuzzer::select_best_iid_pivot(
        std::unordered_map<branching_node*, iid_pivot_props> const&  pivots,
        natural_32_bit const  max_input_width,
        random_generator_for_natural_32_bit&  random_generator,
        float_32_bit const  LIMIT_STEP
        )
{
    TMPROF_BLOCK();

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


void  fuzzer::compute_histogram_of_false_direction_probabilities(
        natural_32_bit const  input_width,
        std::unordered_set<location_id> const&  pure_loop_bodies,
        std::unordered_map<branching_node*, iid_pivot_props> const&  pivots,
        histogram_of_false_direction_probabilities&  histogram
        )
{
    TMPROF_BLOCK();

    std::unordered_map<location_id::id_type, std::multimap<branching_function_value_type, float_32_bit> > hist_pack;
    {
        std::unordered_set<histogram_of_hit_counts_per_direction const*>  processed_histograms;
        for (auto  it = pivots.begin(); it != pivots.end(); ++it)
            if (it->first->get_num_stdin_bytes() == input_width)
                for (histogram_of_hit_counts_per_direction const*  hist_ptr = it->second.histogram_ptr.get();
                            hist_ptr != nullptr && processed_histograms.insert(hist_ptr).second;
                            hist_ptr = hist_ptr->get_predecessor().get())
                    for (auto const& id_and_hits : hist_ptr->local_hit_counts())
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

    }

    for (auto const&  id_and_pack : hist_pack)
    {
        auto const&  pack = id_and_pack.second;
        vecf32  probabilities;
        for (auto  it = pack.rbegin(); it != pack.rend(); ++it)
            if (std::fabs(pack.begin()->first - it->first) >= 1e-6f)
            {
                float_32_bit const  t = (float_32_bit)(-it->first / (pack.begin()->first - it->first));
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
        std::vector<branching_node*> const&  loop_boundaries,
        random_generator_for_natural_32_bit&  random_generator,
        float_32_bit const  LIMIT_STEP,
        branching_node*  fallback_node
        )
{
    ASSUMPTION(LIMIT_STEP >= 0.0f && LIMIT_STEP <= 1.0f);
    if (!loop_boundaries.empty())
    {
        float_32_bit const  probability{ get_random_float_32_bit_in_range(0.0f, 1.0f, random_generator) };
        std::size_t  i = 0;
        for (float_32_bit  limit = LIMIT_STEP;
                i != loop_boundaries.size() && probability > limit;
                limit += LIMIT_STEP * (1.0f - limit)
                )
            ++i;
        for ( ; i < loop_boundaries.size(); ++i)
        {
            branching_node* const  node = loop_boundaries.at((loop_boundaries.size() - 1U) - i);
            if (!node->is_closed())
                return node;
        }
    }
    return fallback_node;
}


std::shared_ptr<fuzzer::probability_generator_random_uniform>  fuzzer::compute_probability_generators_for_locations(
        histogram_of_false_direction_probabilities const&  probabilities,
        histogram_of_hit_counts_per_direction::hit_counts_map const&  hit_counts,
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


fuzzer::fuzzer(termination_info const&  info)
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
            [this](location_id const  loc_id) {
                    auto const  it = iid_pivots.find(loc_id);
                    return it == iid_pivots.end() ? nullptr : it->second.pivot_with_lowest_abs_value;
                    },
            &statistics
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
            terminate();
            termination_reason = TERMINATION_REASON::ALL_REACHABLE_BRANCHINGS_COVERED;
            return false;
        }
    }

    if (num_remaining_seconds() <= 0L)
    {
        terminate();
        termination_reason = TERMINATION_REASON::TIME_BUDGET_DEPLETED;
        return false;
    }

    if (num_remaining_driver_executions() <= 0L)
    {
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


execution_record::execution_flags  fuzzer::round_end()
{
    TMPROF_BLOCK();

    execution_record::execution_flags const  flags = process_execution_results();

    time_point_current = std::chrono::steady_clock::now();
    ++num_driver_executions;

    return flags;
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
        return 0;

    stdin_bits_and_types_pointer const  bits_and_types{ std::make_shared<stdin_bits_and_types>(
            iomodels::iomanager::instance().get_stdin()->get_bytes(),
            iomodels::iomanager::instance().get_stdin()->get_types()
            ) };
    execution_trace_pointer const  trace = std::make_shared<execution_trace>(iomodels::iomanager::instance().get_trace());
    br_instr_execution_trace_pointer const  br_instr_trace = std::make_shared<br_instr_execution_trace>(iomodels::iomanager::instance().get_br_instr_trace());

    execution_record::execution_flags  exe_flags { 0U };

    if (!trace->empty())
    {
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
                for (branching_node*  node = construction_props.leaf; node != nullptr && node->is_closed(); node = node->predecessor)
                    node->set_closed(false);

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
                primary_coverage_targets.process_potential_coverage_target({ node, false });

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

        if (iomodels::iomanager::instance().get_termination() == instrumentation::target_termination::medium_overflow)
        {
            ++statistics.traces_to_medium_overflow;
            exe_flags |= execution_record::MEDIUM_OVERFLOW;
        }

        if (construction_props.any_location_discovered)
            exe_flags |= execution_record::BRANCH_DISCOVERED;

        if (!construction_props.covered_locations.empty())
            exe_flags |= execution_record::BRANCH_COVERED;
    }
    else
    {
        recorder().on_trace_mapped_to_tree(nullptr);

        if (iomodels::iomanager::instance().get_termination() == instrumentation::target_termination::crash)
        {
            ++statistics.traces_to_crash;
            exe_flags |= execution_record::EXECUTION_CRASHES;
        }

        if (iomodels::iomanager::instance().get_termination() == instrumentation::target_termination::boundary_condition_violation)
        {
            ++statistics.traces_to_boundary_violation;
            exe_flags |= execution_record::BOUNDARY_CONDITION_VIOLATION;
        }

        if (iomodels::iomanager::instance().get_termination() == instrumentation::target_termination::medium_overflow)
        {
            ++statistics.traces_to_medium_overflow;
            exe_flags |= execution_record::MEDIUM_OVERFLOW;
        }

        if (state == STARTUP)
            exe_flags |= execution_record::EMPTY_STARTUP_TRACE;
    }

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
            for (branching_node*  node = sensitivity.get_node(); node != nullptr; node = node->predecessor)
                if (!node->is_closed())
                {
                    update_close_flags_from(node);
                    break;
                }
            collect_iid_pivots_from_sensitivity_results();
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


void  fuzzer::collect_iid_pivots_from_sensitivity_results()
{
    TMPROF_BLOCK();

    ASSUMPTION(state == SENSITIVITY && sensitivity.get_node() != nullptr);

    std::vector<std::pair<branching_node*, iid_pivot_props*> >  pivots;
    for (branching_node* node : sensitivity.get_changed_nodes())
        if (node->is_iid_branching() && !covered_branchings.contains(node->get_location_id()))
        {
            iid_location_props&  loc_props = iid_pivots[node->get_location_id()];
            auto const  pivot_it_and_state = loc_props.pivots.insert({ node, {} });
            if (pivot_it_and_state.second)
            {
                if (loc_props.pivot_with_lowest_abs_value == nullptr
                        || std::fabs(node->best_coverage_value) < std::fabs(loc_props.pivot_with_lowest_abs_value->best_coverage_value))
                    loc_props.pivot_with_lowest_abs_value = node;

                pivots.push_back({ node, &pivot_it_and_state.first->second });
            }
        }
    if (pivots.empty())
        return;

    std::unordered_map<location_id, std::unordered_set<location_id> >  loop_heads_to_bodies;
    std::vector<loop_boundary_props>  loops;
    detect_loops_along_path_to_node(sensitivity.get_node(), loop_heads_to_bodies, &loops);

    std::vector<branching_node*>  loop_boundaries;
    compute_loop_boundaries(loops, loop_boundaries);

    std::vector<std::pair<branching_node*, std::unordered_set<location_id> const*> >  index_for_loop_heads_map;
    {
        std::unordered_map<location_id, branching_node*>  first_occurrences_of_loop_exits;
        for (loop_boundary_props const&  props : loops)
        {
            auto const  it_and_state = first_occurrences_of_loop_exits.insert({ props.exit->get_location_id(), props.exit });
            if (!it_and_state.second && props.exit->get_trace_index() < it_and_state.first->second->get_trace_index())
                it_and_state.first->second = props.exit;
        }
        for (auto const&  loc_and_node : first_occurrences_of_loop_exits)
            index_for_loop_heads_map.push_back({
                    loc_and_node.second,
                    &loop_heads_to_bodies.at(loc_and_node.second->get_location_id())
                    });
        std::sort(
                index_for_loop_heads_map.begin(),
                index_for_loop_heads_map.end(),
                [](decltype(index_for_loop_heads_map)::value_type const&  left,
                   decltype(index_for_loop_heads_map)::value_type const&  right)
                   { return left.first->get_trace_index() < right.first->get_trace_index(); }
                );
    }

    for (auto const&  pivot_and_props : pivots)
    {
        for (std::size_t  i = 0U; i != loop_boundaries.size(); ++i)
        {
            branching_node* const  boundary_node = loop_boundaries.at(i);
            if (pivot_and_props.first->get_trace_index() < boundary_node->get_trace_index())
                break;
            pivot_and_props.second->loop_boundaries.push_back(boundary_node);
        }

        std::unordered_map<location_id, std::unordered_set<location_id> >  pivot_loop_heads_to_bodies;
        for (std::size_t  i = 0U; i != index_for_loop_heads_map.size(); ++i)
        {
            auto const&  node_and_body = index_for_loop_heads_map.at(i);
            if (pivot_and_props.first->get_trace_index() < node_and_body.first->get_trace_index())
                break;
            pivot_loop_heads_to_bodies.insert({ node_and_body.first->get_location_id(), *node_and_body.second });
        }
        for (auto const&  loc_and_bodies : pivot_loop_heads_to_bodies)
            pivot_and_props.second->pure_loop_bodies.insert(loc_and_bodies.second.begin(), loc_and_bodies.second.end());
        for (auto const&  loc_and_bodies : pivot_loop_heads_to_bodies)
            pivot_and_props.second->pure_loop_bodies.erase(loc_and_bodies.first);
    }

    std::sort(pivots.begin(), pivots.end(),
            [](std::pair<branching_node*, iid_pivot_props*> const&  left, std::pair<branching_node*, iid_pivot_props*> const&  right) {
                    return left.first->get_trace_index() < right.first->get_trace_index();
                    }
            );

    struct  histograms_builder_and_pure_loop_bodies_cleaner
    {
        void  run(std::vector<std::pair<branching_node*, iid_pivot_props*> > const&  pivots)
        {
            pivots.begin()->second->histogram_ptr = histogram_of_hit_counts_per_direction::create(nullptr);
            extend_hit_counts_histogram(pivots.begin()->first, nullptr, pivots.begin()->second->histogram_ptr);

            extend_hit_counts_map(pivots.begin()->second->histogram_ptr);
            prune_pure_loop_bodies(pivots.begin()->second->pure_loop_bodies);

            for (auto  it_prev = pivots.begin(), it = std::next(it_prev); it != pivots.end(); it_prev = it, ++it)
            {
                it->second->histogram_ptr = histogram_of_hit_counts_per_direction::create(it_prev->second->histogram_ptr);
                extend_hit_counts_histogram(it->first, it_prev->first, it->second->histogram_ptr);

                extend_hit_counts_map(it->second->histogram_ptr);
                prune_pure_loop_bodies(it->second->pure_loop_bodies);
            }
        }

    private:

        histogram_of_hit_counts_per_direction::hit_counts_map  hit_counts;

        void  extend_hit_counts_histogram(
                branching_node const*  pivot,
                branching_node const*  end,
                histogram_of_hit_counts_per_direction::pointer_type const  histogram_ptr
                )
        {
            ASSUMPTION(pivot != nullptr);
            histogram_of_hit_counts_per_direction::hit_counts_map&  target_hit_counts{ histogram_ptr->local_hit_counts_ref() };
            for (branching_node const*  node = pivot; node->predecessor != end; node = node->predecessor)
            {
                location_id::id_type const  id{ node->predecessor->get_location_id().id };
                auto const  it_and_state = target_hit_counts.insert({ id, {} });
                if (it_and_state.second)
                {
                    auto const  it_pred = hit_counts.find(id);
                    if (it_pred != hit_counts.end())
                        it_and_state.first->second = it_pred->second;
                }
                ++it_and_state.first->second[node->predecessor->successor_direction(node)];
            }
        }

        void  extend_hit_counts_map(histogram_of_hit_counts_per_direction::pointer_type const  histogram_ptr)
        {
            histogram_of_hit_counts_per_direction::hit_counts_map  hit_counts_temp{ histogram_ptr->local_hit_counts() };
            hit_counts_temp.insert(hit_counts.begin(), hit_counts.end());
            std::swap(hit_counts, hit_counts_temp);
        }

        void  prune_pure_loop_bodies(std::unordered_set<location_id>&  pure_loop_bodies)
        {
            for (auto  it = pure_loop_bodies.begin(); it != pure_loop_bodies.end(); )
                if (hit_counts.contains(it->id))
                    ++it;
                else
                    it = pure_loop_bodies.erase(it);
        }
    };

    histograms_builder_and_pure_loop_bodies_cleaner{}.run(pivots);
}


void  fuzzer::select_next_state()
{
    TMPROF_BLOCK();

    INVARIANT(sensitivity.is_ready() && typed_minimization.is_ready() && minimization.is_ready() && bitshare.is_ready());

    branching_node*  winner = nullptr;
    winner = primary_coverage_targets.get_best(max_input_width);
    if (winner == nullptr && !entry_branching->is_closed())
        winner = select_iid_coverage_target();

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
            get_random_natural_32_bit_in_range(0, (natural_32_bit)iid_pivots.size() - 1, generator_for_iid_location_selection)
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

    histogram_of_hit_counts_per_direction::hit_counts_map  hit_counts;
    it_pivot->second.histogram_ptr->merge(hit_counts);

    probability_generators_for_locations  generators;
    auto const  random_uniform_generator = compute_probability_generators_for_locations(
            histogram,
            hit_counts,
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
                it_pivot->second.loop_boundaries,
                it_pivot->second.generator_for_start_node_selection,
                0.75f,
                entry_branching
                );

        winner = monte_carlo_search(start_node, histogram, generators, *random_uniform_generator);

        ++statistics.strategy_monte_carlo;
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

        primary_coverage_targets.erase(node);
        coverage_failures_with_hope.erase(node);

        auto const  it_iid_loc = iid_pivots.find(node->get_location_id());
        if (it_iid_loc != iid_pivots.end())
        {
            iid_location_props&  props = it_iid_loc->second;
            auto const  it_pivot = props.pivots.find(node);
            if (it_pivot != props.pivots.end())
            {
                props.pivots.erase(it_pivot);
                if (props.pivots.empty())
                    iid_pivots.erase(it_iid_loc);
                else if (node == props.pivot_with_lowest_abs_value)
                {
                    props.pivot_with_lowest_abs_value = props.pivots.begin()->first;
                    for (auto  it = std::next(props.pivots.begin()); it != props.pivots.end(); ++it)
                        if (std::fabs(it->first->best_coverage_value)
                                < std::fabs(props.pivot_with_lowest_abs_value->best_coverage_value))
                            props.pivot_with_lowest_abs_value = it->first;
                }
            }
        }

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

            primary_coverage_targets.process_potential_coverage_target({ node, true });

            ++statistics.coverage_failure_resets;
        }
    }
    coverage_failures_with_hope.clear();
    return !primary_coverage_targets.empty();
 }


}
