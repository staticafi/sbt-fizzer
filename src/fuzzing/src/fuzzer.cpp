#include <fuzzing/fuzzer.hpp>
#include <fuzzing/progress_recorder.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/development.hpp>
#include <utility/timeprof.hpp>
#include <map>

namespace  fuzzing {


fuzzer::primary_coverage_target_branchings::primary_coverage_target_branchings(
        std::function<bool(location_id)> const&  is_covered_,
        std::function<branching_node*(location_id)> const&  iid_pivot_with_lowest_abs_value_,
        performance_statistics* const  statistics_ptr_
        )
    : loop_heads_sensitive{}
    , loop_heads_others{}
    , sensitive{}
    , untouched{}
    , iid_twins_sensitive{}
    , iid_twins_others{}
    , sensitive_counts{}
    , untouched_counts{}
    , sensitive_start_index{ 0U }
    , untouched_start_index{ 0U }
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

        for (branching_node*  node = end_node; node != nullptr; node = node->get_predecessor())
            if (loop_heads_to_bodies.contains(node->get_location_id()))
            {
                natural_32_bit const  input_class = get_input_width_class(node->get_num_stdin_bytes());
                auto&  state_and_node = input_class_coverage.at(input_class);
                if (!state_and_node.first)
                {
                    if (node->is_pending())
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
        {
            if (width_and_state_and_node.second.second->was_sensitivity_performed())
                loop_heads_sensitive.insert(width_and_state_and_node.second.second);
            else
                loop_heads_others.insert(width_and_state_and_node.second.second);
        }
}


void  fuzzer::primary_coverage_target_branchings::process_potential_coverage_target(
        std::pair<branching_node*, bool> const&  node_and_flag
        )
{
    auto const [node, flag] = node_and_flag;
    ASSUMPTION(node != nullptr);
    if (node->is_pending() && !is_covered(node->get_location_id()))
    {
        if (node->was_sensitivity_performed())
        {
            if (!node->get_sensitive_stdin_bits().empty() && !node->was_local_search_performed())
                sensitive.insert(node_and_flag);
        }
        else
        {
            branching_node* const  iid_pivot = iid_pivot_with_lowest_abs_value(node->get_location_id());
            if (iid_pivot != nullptr)
            {
                if (std::fabs(node->get_best_value()) < std::fabs(iid_pivot->get_best_value()))
                {
                    auto& iid_twins{ node->was_sensitivity_performed() ? iid_twins_sensitive : iid_twins_others };
                    auto const  it_and_state = iid_twins.insert({ node->get_location_id(), node_and_flag });
                    if (!it_and_state.second &&
                            std::fabs(node->get_best_value()) < std::fabs(it_and_state.first->second.first->get_best_value()))
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
    loop_heads_sensitive.erase(node);
    loop_heads_others.erase(node);
    sensitive.erase(node);
    untouched.erase(node);
    for (auto iid_twins : { &iid_twins_sensitive, &iid_twins_others })
    {
        auto const  it = iid_twins->find(node->get_location_id());
        if (it != iid_twins->end() && it->second.first == node)
            iid_twins->erase(it);
    }
}


bool  fuzzer::primary_coverage_target_branchings::empty() const
{
    return  loop_heads_sensitive.empty() && loop_heads_others.empty() &&
            sensitive.empty() && untouched.empty() &&
            iid_twins_sensitive.empty() && iid_twins_others.empty();
}


void  fuzzer::primary_coverage_target_branchings::clear()
{
    loop_heads_sensitive.clear();
    loop_heads_others.clear();
    sensitive.clear();
    untouched.clear();
    iid_twins_sensitive.clear();
    iid_twins_others.clear();
}


void  fuzzer::primary_coverage_target_branchings::do_cleanup()
{
    TMPROF_BLOCK();

    std::unordered_set<branching_node*>  loop_heads;
    loop_heads.swap(loop_heads_sensitive);
    loop_heads.insert(loop_heads_others.begin(), loop_heads_others.end());
    loop_heads_others.clear();
    for (auto  node : loop_heads)
        if (node->is_pending())
        {
            if (node->was_sensitivity_performed())
                loop_heads_sensitive.insert(node);
            else
                loop_heads_others.insert(node);
        }

    std::unordered_map<branching_node*, bool>  work_set;
    work_set.swap(sensitive);
    work_set.insert(untouched.begin(), untouched.end());
    untouched.clear();
    for (auto iid_twins : { &iid_twins_sensitive, &iid_twins_others })
        for (auto const&  loc_and_props : *iid_twins)
            work_set.insert(loc_and_props.second);
    iid_twins_sensitive.clear();
    iid_twins_others.clear();
    while (!work_set.empty())
    {
        std::pair<branching_node*, bool> const  node_and_flag = *work_set.begin();
        work_set.erase(work_set.begin());
        process_potential_coverage_target(node_and_flag);
    }
}


branching_node*  fuzzer::primary_coverage_target_branchings::get_best_others(natural_32_bit const  max_input_width)
{
    TMPROF_BLOCK();

    std::vector<std::function<branching_node*()> > const  best_node_getters {
        [this](){
            branching_node*  best_node = nullptr;
            if (!loop_heads_others.empty())
            {
                best_node = *loop_heads_others.begin();
                ++statistics->strategy_primary_loop_head;
                recorder().on_strategy_turn_primary_loop_head();
            }
            return best_node;
        },
        [this, max_input_width](){
            branching_node*  best_node{ get_best(untouched, untouched_counts, max_input_width) };
            if (best_node != nullptr)
            {
                ++untouched_counts.at(best_node->get_location_id().id);
                ++statistics->strategy_primary_untouched;
                recorder().on_strategy_turn_primary_sensitive();
            }
            return best_node;
        }
    };
    untouched_start_index = (untouched_start_index + 1U) % best_node_getters.size();
    for (std::size_t  i = 0UL; i != best_node_getters.size(); ++i)
    {
        std::size_t  idx = (untouched_start_index + i) % best_node_getters.size();
        branching_node* const  best_node{ best_node_getters.at(idx)() };
        if (best_node != nullptr)
            return best_node;
    }

    if (!iid_twins_others.empty())
    {
        auto const  it = iid_twins_others.begin();
        if (!it->second.second) 
        {
            collect_loop_heads_along_path_to_node(it->second.first);
            it->second.second = true;
            if (!loop_heads_others.empty())
                return get_best_others(max_input_width);
        }
        ++statistics->strategy_primary_iid_twins;
        recorder().on_strategy_turn_primary_iid_twins();
        return it->second.first;
    }

    return nullptr;
}


branching_node*  fuzzer::primary_coverage_target_branchings::get_best_sensitive(natural_32_bit const  max_input_width)
{
    TMPROF_BLOCK();

    std::vector<std::function<branching_node*()> > const  best_node_getters {
        [this](){
            branching_node*  best_node = nullptr;
            if (!loop_heads_sensitive.empty())
            {
                best_node = *loop_heads_sensitive.begin();
                ++statistics->strategy_primary_loop_head;
                recorder().on_strategy_turn_primary_loop_head();
            }
            return best_node;
        },
        [this, max_input_width](){
            branching_node*  best_node{ get_best(sensitive, sensitive_counts, max_input_width) };
            if (best_node != nullptr)
            {
                ++sensitive_counts.at(best_node->get_location_id().id);
                ++statistics->strategy_primary_sensitive;
                recorder().on_strategy_turn_primary_sensitive();
            }
            return best_node;
        }
    };
    sensitive_start_index = (sensitive_start_index + 1U) % best_node_getters.size();
    for (std::size_t  i = 0UL; i != best_node_getters.size(); ++i)
    {
        std::size_t  idx = (sensitive_start_index + i) % best_node_getters.size();
        branching_node* const  best_node{ best_node_getters.at(idx)() };
        if (best_node != nullptr)
            return best_node;
    }

    if (!iid_twins_sensitive.empty())
    {
        auto const  it = iid_twins_sensitive.begin();
        if (!it->second.second) 
        {
            collect_loop_heads_along_path_to_node(it->second.first);
            it->second.second = true;
            if (!loop_heads_sensitive.empty())
                return get_best_sensitive(max_input_width);
        }
        ++statistics->strategy_primary_iid_twins;
        recorder().on_strategy_turn_primary_iid_twins();
        return it->second.first;
    }

    return nullptr;
}


void  fuzzer::primary_coverage_target_branchings::update_counts(
        std::unordered_map<location_id::id_type, natural_32_bit>&  counts,
        std::unordered_map<branching_node*, bool> const&  data
        )
{
    std::unordered_map<location_id::id_type, natural_32_bit>  old_counts;
    old_counts.swap(counts);
    natural_32_bit  min_count{ 0U };
    for (auto const&  id_and_count : old_counts)
        min_count = std::min(min_count, id_and_count.second);
    for (auto const&  node_and_bool : data)
    {
        auto const  it = old_counts.find(node_and_bool.first->get_location_id().id);
        counts[node_and_bool.first->get_location_id().id] = it == old_counts.end() ? 0U : it->second - min_count;
    }
}


branching_node*  fuzzer::primary_coverage_target_branchings::get_best(
        std::unordered_map<branching_node*, bool>&  targets,
        std::unordered_map<location_id::id_type, natural_32_bit>&  counts,
        natural_32_bit const  max_input_width
        )
{
    if (targets.empty())
        return nullptr;

    struct  branching_node_with_less_than
    {
        branching_node_with_less_than(
                branching_node* const  node_,
                natural_32_bit const  count_,
                natural_32_bit const  max_input_width
                )
            : node{ node_ }
            , count{ count_ }
            , distance_to_central_input_width_class{
                    std::abs((integer_32_bit)get_input_width_class(max_input_width / 2U) -
                             (integer_32_bit)get_input_width_class(node->get_num_stdin_bytes()))
                    }
        {}
        operator  branching_node*() const { return node; }
        bool  operator<(branching_node_with_less_than const&  other) const
        {
            if (count < other.count)
                return true;
            if (count > other.count)
                return false;
            if (node->get_sensitive_stdin_bits().size() < other.node->get_sensitive_stdin_bits().size())
                return true;
            if (node->get_sensitive_stdin_bits().size() > other.node->get_sensitive_stdin_bits().size())
                return false;
            if (distance_to_central_input_width_class < other.distance_to_central_input_width_class)
                return true;
            if (distance_to_central_input_width_class > other.distance_to_central_input_width_class)
                return false;
            if (node->get_num_stdin_bytes() < other.node->get_num_stdin_bytes())
                return true;
            if (node->get_num_stdin_bytes() > other.node->get_num_stdin_bytes())
                return false;
            if (node->get_trace_index() < other.node->get_trace_index())
                return true;
            if (node->get_trace_index() > other.node->get_trace_index())
                return false;
            return node->get_max_successors_trace_index() > other.node->get_max_successors_trace_index();
        }
    private:
        branching_node*  node;
        natural_32_bit  count;
        integer_32_bit  distance_to_central_input_width_class;
    };

    update_counts(counts, targets);

    branching_node_with_less_than  best{ targets.begin()->first, counts.at(targets.begin()->first->get_location_id().id), max_input_width };
    for (auto  it = std::next(targets.begin()); it != targets.end(); ++it)
    {
        branching_node_with_less_than const  current{ it->first, counts.at(it->first->get_location_id().id), max_input_width };
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


fuzzer::input_flow_analysis_thread::input_flow_analysis_thread(sala::Program const* sala_program_ptr)
    : state{ READY }
    , io_setup{
            iomodels::iomanager::instance().clone_stdin(),
            iomodels::iomanager::instance().clone_stdout(),
            iomodels::iomanager::instance().get_config()
            }
    , request{}
    , input_flow{ sala_program_ptr, &io_setup }
    , worker_stop_flag{ false }
    , mutex{}
    , worker{ std::thread(&input_flow_analysis_thread::worker_thread_procedure, this) }
{}


bool  fuzzer::input_flow_analysis_thread::is_ready() const
{
    std::lock_guard<std::mutex> const lock(mutex);
    return state == READY;
}


bool  fuzzer::input_flow_analysis_thread::is_busy() const
{
    std::lock_guard<std::mutex> const lock(mutex);
    return state == STEADY || state == WORKING;
}


bool  fuzzer::input_flow_analysis_thread::is_finished() const
{
    std::lock_guard<std::mutex> const lock(mutex);
    return state == FINISHED;
}


bool  fuzzer::input_flow_analysis_thread::is_terminated() const
{
    std::lock_guard<std::mutex> const lock(mutex);
    return state == TERMINATED;
}


void  fuzzer::input_flow_analysis_thread::start(
        branching_node* const  node_ptr,
        natural_32_bit const  execution_id,
        float_64_bit const  remaining_seconds
        )
{
    ASSUMPTION(is_ready());

    std::lock_guard<std::mutex> const lock(mutex);

    request.data.input_ptr = node_ptr->get_best_stdin();
    request.data.trace_ptr = node_ptr->get_best_trace();
    request.data.trace_size = node_ptr->get_trace_index() + 1U;
    request.data.sensitive_bits.clear();
    request.changed_nodes.clear();
    request.last_node = nullptr;
    request.execution_id = execution_id;
    request.remaining_seconds = remaining_seconds;

    state = STEADY;
}


void  fuzzer::input_flow_analysis_thread::stop()
{
    {
        std::lock_guard<std::mutex> const lock(mutex);
        worker_stop_flag = true;
    }
    if (worker.joinable())
        worker.join();
    state = TERMINATED;
}


branching_node*  fuzzer::input_flow_analysis_thread::get_node() const
{
    ASSUMPTION(is_ready());
    return request.last_node;
}


std::unordered_set<branching_node*> const&  fuzzer::input_flow_analysis_thread::get_changed_nodes()
{
    ASSUMPTION(is_ready());
    return request.changed_nodes;
}


void  fuzzer::input_flow_analysis_thread::apply_results(branching_node* const  entry_node)
{
    ASSUMPTION(is_finished());

    request.changed_nodes.clear();
    request.last_node = nullptr;

    branching_node*  node{ entry_node };
    std::size_t  trace_index{ 0ULL };
    while (node != nullptr && trace_index < request.data.trace_size)
    {
        ASSUMPTION(node->get_trace_index() == trace_index);

        auto const&  info{ request.data.trace_ptr->at(trace_index) };
        if (node->get_location_id() != info.id)
            break;

        request.last_node = node;
        if (trace_index < request.data.sensitive_bits.size())
            for (auto const  bit_idx : request.data.sensitive_bits.at(trace_index))
                if (node->insert_sensitive_stdin_bit(bit_idx))
                    request.changed_nodes.insert(node);
        if (!node->was_sensitivity_performed())
            request.changed_nodes.insert(node);

        node->set_sensitivity_performed(request.execution_id);

        node = node->successor(info.direction).pointer;
        ++trace_index;
    }

    {
        std::lock_guard<std::mutex> const lock(mutex);
        state = READY;
    }
}

input_flow_analysis::performance_statistics const&  fuzzer::input_flow_analysis_thread::get_statistics() const
{
    ASSUMPTION(!is_busy() || is_terminated());
    return input_flow.get_statistics();
}


void fuzzer::input_flow_analysis_thread::worker_thread_procedure()
{
    while (true)
    {
        input_flow_analysis::computation_io_data*  data_ptr{ nullptr };
        {
            std::lock_guard<std::mutex> const lock(mutex);
            if (worker_stop_flag)
                break;
            if (state == STEADY)
            {
                data_ptr = &request.data;
                state = WORKING;
            }
        }
        if (data_ptr == nullptr)
        {
            //std::this_thread::yield();
            using namespace std::chrono_literals;
            std::this_thread::sleep_for(10ms);
            continue;
        }

        std::chrono::system_clock::time_point const  start_time = std::chrono::system_clock::now();
        input_flow.run(data_ptr, [this, start_time](std::string& error_message) {
            double const num_seconds = std::chrono::duration<double>(std::chrono::system_clock::now() - start_time).count();
            if (num_seconds >= request.remaining_seconds)
            {
                error_message = "[TIME OUT] The time budget " + std::to_string(request.remaining_seconds) + "s for the execution was exhausted.";
                return true;
            }
            bool do_stop;
            {
                std::lock_guard<std::mutex> const lock(mutex);
                do_stop = worker_stop_flag;
            }
            if (do_stop)
            {
                error_message = "[FORCE STOP] The computation was stopped forcefully by the signalled flag.";
                return true;
            }
            return false;
        });

        {
            std::lock_guard<std::mutex> const lock(mutex);
            state = FINISHED;
        }
    }
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


std::string const&  fuzzer::get_analysis_name_from_state(STATE state)
{
    static std::unordered_map<STATE, std::string> const  map {
        { STARTUP, "STARTUP" },
        { BITSHARE, "bitshare_analysis" },
        { LOCAL_SEARCH, "local_search" },
        { BITFLIP, "bitflip_analysis" },
        { FINISHED, "FINISHED" },
    };
    return map.at(state);
}


void  fuzzer::update_close_flags_from(branching_node* const  node)
{
    if (node->is_closed() || node->is_pending())
        return;
    branching_node::successor_pointer const&  left = node->successor(false);
    if (left.pointer != nullptr && !left.pointer->is_closed())
        return;
    branching_node::successor_pointer const&  right = node->successor(true);
    if (right.pointer != nullptr && !right.pointer->is_closed())
        return;

    node->set_closed();

    recorder().on_post_node_closed(node);

    if (node->get_predecessor() != nullptr)
        update_close_flags_from(node->get_predecessor());
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
    for (branching_node*  node = end_node, *succ_node = node; node != nullptr; succ_node = node, node = node->get_predecessor())
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
            while (props.entry->get_predecessor() != nullptr
                        && (props.entry->get_predecessor()->get_location_id() == props.exit->get_location_id() ||
                            loop_body.contains(props.entry->get_predecessor()->get_location_id())))
                props.entry = props.entry->get_predecessor();
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
            , abs_value{ std::fabs(pivot->get_best_value()) }
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
                                std::fabs(it->first->get_best_value()),
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

    INVARIANT(pivot != nullptr && pivot->is_pending());

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
    while (pivot->get_predecessor()->is_closed())
        pivot = pivot->get_predecessor();

    while (pivot->get_predecessor() != end_node)
    {
        branching_node* const  successor{ monte_carlo_step(pivot->get_predecessor(), histogram, generators, location_miss_generator) };
        if (successor != pivot)
            break;
        pivot = pivot->get_predecessor();
    }

    return { pivot->get_predecessor(), !pivot->get_predecessor()->successor_direction(pivot) };
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
    else if (!pivot->is_pending())
        successor = can_go_left ? left : right;

    return successor;
}


fuzzer::fuzzer(termination_info const&  info, sala::Program const* const sala_program_ptr_)
    : sala_program_ptr{ sala_program_ptr_ }

    , termination_props{ info }

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
    , input_flow_thread{ sala_program_ptr }
    , bitshare{}
    , local_search{}
    , bitflip{}

    , max_input_width{ 0U }

    , generator_for_iid_location_selection{ 1U }
    , generator_for_iid_approach_selection{ 1U }
    , generator_for_generator_selection{ 1U }

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
    input_flow_thread.stop();
    bitshare.stop();
    local_search.stop();
    bitflip.stop();
}


bool  fuzzer::round_begin(TERMINATION_REASON&  termination_reason)
{
    TMPROF_BLOCK();

    iomodels::iomanager::instance().get_stdin()->clear();
    iomodels::iomanager::instance().get_stdout()->clear();

    vecb  stdin_bits;
    if (!generate_next_input(stdin_bits, termination_reason))
        return false;
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


std::pair<execution_record::execution_flags, std::string const&>  fuzzer::round_end()
{
    TMPROF_BLOCK();

    execution_record::execution_flags const  flags = process_execution_results();

    ++num_driver_executions;

    return { flags, get_analysis_name_from_state(state) };
}


bool  fuzzer::generate_next_input(vecb&  stdin_bits, TERMINATION_REASON&  termination_reason)
{
    TMPROF_BLOCK();

    while (true)
    {
        if (get_performed_driver_executions() > 0U)
        {
            if (uncovered_branchings.empty())
            {
                terminate();
                termination_reason = TERMINATION_REASON::ALL_REACHABLE_BRANCHINGS_COVERED;
                return false;
            }
        }

        time_point_current = std::chrono::steady_clock::now();
        if (num_remaining_seconds() <= 0.0)
        {
            terminate();
            termination_reason = TERMINATION_REASON::TIME_BUDGET_DEPLETED;
            return false;
        }

        if (num_remaining_driver_executions() <= 0U)
        {
            terminate();
            termination_reason = TERMINATION_REASON::EXECUTIONS_BUDGET_DEPLETED;
            return false;
        }

        if (input_flow_thread.is_finished())
        {
            input_flow_thread.apply_results(entry_branching);

            for (branching_node*  node = input_flow_thread.get_node(); node != nullptr; node = node->get_predecessor())
                if (!node->is_closed())
                {
                    update_close_flags_from(node);
                    break;
                }
            if (input_flow_thread.get_node() != nullptr)
                collect_iid_pivots_from_sensitivity_results();
            primary_coverage_targets.do_cleanup();
            if (state == BITFLIP)
            {
                do_cleanup();
                select_next_state();
            }
        }
        if (input_flow_thread.is_ready())
        {
            branching_node*  winner{ primary_coverage_targets.get_best_others(max_input_width) };
            if (winner == nullptr && entry_branching != nullptr && !entry_branching->is_closed())
            {
                winner = select_iid_coverage_target();
                if (winner != nullptr && winner->was_sensitivity_performed())
                    winner = nullptr;
            }
            if (winner != nullptr)
                try_start_input_flow_analysis(winner);
        }

        switch (state)
        {
            case STARTUP:
                if (get_performed_driver_executions() == 0U)
                    return true;
                break;

            case BITSHARE:
                if (bitshare.generate_next_input(stdin_bits))
                    return true;
                break;

            case LOCAL_SEARCH:
                if (local_search.generate_next_input(stdin_bits))
                    return true;
                break;

            case BITFLIP:
                if (bitflip.generate_next_input(stdin_bits))
                    return true;
                break;

            case FINISHED:
                if (!apply_coverage_failures_with_hope())
                    return true;
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
                    trace->front().xor_like_branching_function,
                    trace->front().predicate,
                    nullptr,
                    bits_and_types,
                    trace,
                    br_instr_trace,
                    num_driver_executions
                    );
            construction_props.diverging_node = entry_branching;

            ++statistics.nodes_created;
        }

        construction_props.leaf = entry_branching;

        trace_index_type  trace_index = 0;
        for (; true; ++trace_index)
        {
            branching_coverage_info const&  info = trace->at(trace_index);

            INVARIANT(construction_props.leaf->get_location_id() == info.id);

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

            // Here we try to remove bad float (INF, NaN) from 'info.value'.
            // It would be better, if fuzzer and analyses could deal with bad floats, but that is complicated. 
            if (!std::isfinite(info.value) || std::isnan(info.value))
            {
                branching_function_value_type&  value_ref{ const_cast<branching_function_value_type&>(info.value) };
                switch (info.predicate)
                {
                    case BRANCHING_PREDICATE::BP_EQUAL:
                        value_ref = info.direction ? 0.0 : std::numeric_limits<branching_function_value_type>::max();
                        break;
                    case BRANCHING_PREDICATE::BP_UNEQUAL:
                        value_ref = info.direction ? std::numeric_limits<branching_function_value_type>::max() : 0.0;
                        break;
                    case BRANCHING_PREDICATE::BP_LESS_EQUAL:
                    case BRANCHING_PREDICATE::BP_LESS:
                        value_ref = (info.direction ? -1.0 : 1.0) * std::numeric_limits<branching_function_value_type>::max();
                        break;
                        break;
                    case BRANCHING_PREDICATE::BP_GREATER:
                    case BRANCHING_PREDICATE::BP_GREATER_EQUAL:
                        value_ref = (info.direction ? 1.0 : -1.0) * std::numeric_limits<branching_function_value_type>::max();
                        break;
                    default: UNREACHABLE(); break;
                }
            }

            if (!construction_props.leaf->is_direction_unexplored(false) && !construction_props.leaf->is_direction_unexplored(true))
                construction_props.leaf->release_best_data(false);
            else if (std::fabs(info.value) < std::fabs(construction_props.leaf->get_best_value()))
                construction_props.leaf->update_best_data(bits_and_types, trace, br_instr_trace, num_driver_executions);

            construction_props.leaf->set_max_successors_trace_index(std::max(
                    construction_props.leaf->get_max_successors_trace_index(),
                    (trace_index_type)(trace->size() - 1)
                    ));

            if (trace_index + 1 == trace->size())
                break;

            if (construction_props.leaf->successor(info.direction).pointer == nullptr)
            {
                for (branching_node*  node = construction_props.leaf; node != nullptr && node->is_closed(); node = node->get_predecessor())
                    node->set_closed(false);

                branching_coverage_info const&  succ_info = trace->at(trace_index + 1);
                construction_props.leaf->set_successor(info.direction, {
                    branching_node::successor_pointer::VISITED,
                    new branching_node(
                        succ_info.id,
                        trace_index + 1,
                        succ_info.num_input_bytes,
                        succ_info.xor_like_branching_function,
                        succ_info.predicate,
                        construction_props.leaf,
                        bits_and_types,
                        trace,
                        br_instr_trace,
                        num_driver_executions
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

            for (branching_node*  node = construction_props.leaf; node != construction_props.diverging_node->get_predecessor(); node = node->get_predecessor())
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

            auto const  it_and_state = branchings_to_crashes.insert(construction_props.leaf->get_location_id());
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
            INVARIANT(bitshare.is_ready() && local_search.is_ready());
            recorder().on_execution_results_available();
            break;

        case BITSHARE:
            INVARIANT(bitshare.is_busy() && local_search.is_ready());
            recorder().on_execution_results_available();
            bitshare.process_execution_results(trace);
            if (!bitshare.get_node()->has_unexplored_direction())
                bitshare.stop();
            break;

        case LOCAL_SEARCH:
            INVARIANT(bitshare.is_ready() && local_search.is_busy());
            local_search.process_execution_results(trace, bits_and_types);
            if (!local_search.get_node()->has_unexplored_direction())
            {
                local_search.stop();
                bitshare.bits_available_for_branching(local_search.get_node(), trace, bits_and_types);
            }
            break;

        case BITFLIP:
            INVARIANT(bitflip.is_busy() && bitshare.is_ready() && local_search.is_ready());
            recorder().on_execution_results_available();
            break;

        default:
            UNREACHABLE();
            break;
    }

    return exe_flags;
}


void  fuzzer::do_cleanup()
{
    TMPROF_BLOCK();

    INVARIANT(
        bitshare.is_ready() &&
        local_search.is_ready() &&
        (state != FINISHED || !primary_coverage_targets.empty())
        );

    switch (state)
    {
        case BITSHARE:
            update_close_flags_from(bitshare.get_node());
            break;
        case LOCAL_SEARCH:
            update_close_flags_from(local_search.get_node());
            if (!covered_branchings.contains(local_search.get_node()->get_location_id()))
                coverage_failures_with_hope.insert(local_search.get_node());
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
        if (covered_branchings.contains((*it)->get_location_id()))
            it = coverage_failures_with_hope.erase(it);
        else
            ++it;
}


void  fuzzer::collect_iid_pivots_from_sensitivity_results()
{
    TMPROF_BLOCK();

    ASSUMPTION(input_flow_thread.get_node() != nullptr);

    std::vector<std::pair<branching_node*, iid_pivot_props*> >  pivots;
    for (branching_node* node : input_flow_thread.get_changed_nodes())
        if (node->is_iid_branching() && !covered_branchings.contains(node->get_location_id()))
        {
            iid_location_props&  loc_props = iid_pivots[node->get_location_id()];
            auto const  pivot_it_and_state = loc_props.pivots.insert({ node, {} });
            if (pivot_it_and_state.second)
            {
                if (loc_props.pivot_with_lowest_abs_value == nullptr
                        || std::fabs(node->get_best_value()) < std::fabs(loc_props.pivot_with_lowest_abs_value->get_best_value()))
                    loc_props.pivot_with_lowest_abs_value = node;

                pivots.push_back({ node, &pivot_it_and_state.first->second });
            }
        }
    if (pivots.empty())
        return;

    std::unordered_map<location_id, std::unordered_set<location_id> >  loop_heads_to_bodies;
    std::vector<loop_boundary_props>  loops;
    detect_loops_along_path_to_node(input_flow_thread.get_node(), loop_heads_to_bodies, &loops);

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
            for (branching_node const*  node = pivot; node->get_predecessor() != end; node = node->get_predecessor())
            {
                location_id::id_type const  id{ node->get_predecessor()->get_location_id().id };
                auto const  it_and_state = target_hit_counts.insert({ id, {} });
                if (it_and_state.second)
                {
                    auto const  it_pred = hit_counts.find(id);
                    if (it_pred != hit_counts.end())
                        it_and_state.first->second = it_pred->second;
                }
                ++it_and_state.first->second[node->get_predecessor()->successor_direction(node)];
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

    INVARIANT(bitshare.is_ready() && local_search.is_ready());

    branching_node*  winner = nullptr;
    winner = primary_coverage_targets.get_best_sensitive(max_input_width);
    if (winner == nullptr && entry_branching != nullptr && !entry_branching->is_closed())
    {
        winner = select_iid_coverage_target();
        if (winner != nullptr && !winner->was_sensitivity_performed())
        {
            try_start_input_flow_analysis(winner);
            winner = nullptr;
        }
    }

    if (winner == nullptr)
    {
        if (!leaf_branchings.empty() && input_flow_thread.is_busy() || input_flow_thread.is_finished())
        {
            if (bitflip.is_ready())
                bitflip.start(leaf_branchings);
            state = BITFLIP;
        }
        else
            state = FINISHED;
        return;
    }

    INVARIANT(winner->is_pending() && winner->was_sensitivity_performed());

    if (!winner->was_bitshare_performed())
    {
        INVARIANT(!winner->get_sensitive_stdin_bits().empty());
        bitshare.start(winner, num_driver_executions);
        state = BITSHARE;
    }
    else
    {
        INVARIANT(!winner->was_local_search_performed() && !winner->get_sensitive_stdin_bits().empty());
        local_search.start(winner, num_driver_executions);
        state = LOCAL_SEARCH;
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
        else if (!node_and_direction.first->is_pending())
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


bool  fuzzer::try_start_input_flow_analysis(branching_node*  winner)
{
    ASSUMPTION(!winner->was_sensitivity_performed());

    if (!input_flow_thread.is_ready())
        return false;

    while (true)
    {
        branching_node* const  left = winner->successor(false).pointer;
        branching_node* const  right = winner->successor(true).pointer;

        bool const  can_go_left = left != nullptr;
        bool const  can_go_right = right != nullptr;

        if (can_go_left && can_go_right)
            winner = left->get_max_successors_trace_index() >= right->get_max_successors_trace_index() ? left : right;
        else if (can_go_left)
            winner = left;
        else if (can_go_right)
            winner = right;
        else
            break;
    }
    input_flow_thread.start(winner, num_driver_executions, num_remaining_seconds());
    return true;
}


void  fuzzer::remove_leaf_branching_node(branching_node*  node)
{
    TMPROF_BLOCK();

    INVARIANT(bitshare.is_ready() || bitshare.get_node() != node);
    INVARIANT(local_search.is_ready() || local_search.get_node() != node);

    if (leaf_branchings.erase(node) != 0)
        ++statistics.leaf_nodes_destroyed;

    while (node->successor(false).pointer == nullptr && node->successor(true).pointer == nullptr)
    {
        if (leaf_branchings.count(node) != 0)
            break;

        branching_node::successor_pointer::LABEL const  label = std::max(node->successor(false).label, node->successor(true).label);

        branching_node* const  pred = node->get_predecessor();

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
                        if (std::fabs(it->first->get_best_value())
                                < std::fabs(props.pivot_with_lowest_abs_value->get_best_value()))
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
        INVARIANT(node->was_local_search_performed());

        node->perform_failure_reset();

        primary_coverage_targets.process_potential_coverage_target({ node, true });

        ++statistics.coverage_failure_resets;
    }
    coverage_failures_with_hope.clear();
    return !primary_coverage_targets.empty();
 }


}
