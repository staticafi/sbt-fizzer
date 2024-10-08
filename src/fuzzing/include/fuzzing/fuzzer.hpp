#ifndef FUZZING_FUZZER_HPP_INCLUDED
#   define FUZZING_FUZZER_HPP_INCLUDED

#   include <fuzzing/termination_info.hpp>
#   include <fuzzing/sensitivity_analysis.hpp>
#   include <fuzzing/typed_minimization_analysis.hpp>
#   include <fuzzing/minimization_analysis.hpp>
#   include <fuzzing/bitshare_analysis.hpp>
#   include <fuzzing/execution_record.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/math.hpp>
#   include <utility/random.hpp>
#   include <utility/std_pair_hash.hpp>
#   include <string>
#   include <unordered_set>
#   include <unordered_map>
#   include <chrono>
#   include <memory>
#   include <limits>

namespace  fuzzing {


using namespace instrumentation;


struct  fuzzer final
{
    enum struct TERMINATION_REASON
    {
        ALL_REACHABLE_BRANCHINGS_COVERED,
        FUZZING_STRATEGY_DEPLETED,
        TIME_BUDGET_DEPLETED,
        EXECUTIONS_BUDGET_DEPLETED
    };

    struct  performance_statistics
    {
        std::size_t  leaf_nodes_created{ 0 };
        std::size_t  leaf_nodes_destroyed{ 0 };
        std::size_t  nodes_created{ 0 };
        std::size_t  nodes_destroyed{ 0 };
        std::size_t  max_leaf_nodes{ 0 };
        std::size_t  max_input_width{ 0 };
        std::size_t  longest_branch{ 0 };
        std::size_t  traces_to_crash{ 0 };
        std::size_t  traces_to_boundary_violation{ 0 };
        std::size_t  traces_to_medium_overflow{ 0 };
        std::size_t  strategy_primary_loop_head{ 0 };
        std::size_t  strategy_primary_sensitive{ 0 };
        std::size_t  strategy_primary_untouched{ 0 };
        std::size_t  strategy_primary_iid_twins{ 0 };
        std::size_t  strategy_monte_carlo{ 0 };
        std::size_t  coverage_failure_resets{ 0 };
    };

    explicit fuzzer(termination_info const&  info);
    ~fuzzer();

    void  terminate();
    void  stop_all_analyzes();

    termination_info const& get_termination_info() const { return termination_props; }

    long  num_remaining_driver_executions() const { return (long)termination_props.max_executions - (long)num_driver_executions; }
    long  num_remaining_seconds() const { return (long)termination_props.max_seconds - get_elapsed_seconds(); }

    natural_32_bit  get_performed_driver_executions() const { return num_driver_executions; }
    long  get_elapsed_seconds() const { return (long)std::chrono::duration_cast<std::chrono::seconds>(time_point_current - time_point_start).count(); }

    std::unordered_set<location_id> const&  get_covered_branchings() const { return covered_branchings; }
    std::unordered_set<branching_location_and_direction> const&  get_uncovered_branchings() const { return uncovered_branchings; }

    bool  can_make_progress() const { return state != FINISHED; }

    bool  round_begin(TERMINATION_REASON&  termination_reason);
    execution_record::execution_flags  round_end();

    sensitivity_analysis::performance_statistics const&  get_sensitivity_statistics() const { return sensitivity.get_statistics(); }
    typed_minimization_analysis::performance_statistics const&  get_typed_minimization_statistics() const { return typed_minimization.get_statistics(); }
    minimization_analysis::performance_statistics const&  get_minimization_statistics() const { return minimization.get_statistics(); }
    bitshare_analysis::performance_statistics const&  get_bitshare_statistics() const { return bitshare.get_statistics(); }
    performance_statistics const&  get_fuzzer_statistics() const { return statistics; }

private:

    enum STATE
    {
        STARTUP,
        SENSITIVITY,
        TYPED_MINIMIZATION,
        MINIMIZATION,
        BITSHARE,
        FINISHED
    };

    struct  leaf_branching_construction_props
    {
        branching_node*  leaf{ nullptr };
        branching_node*  diverging_node{ nullptr };
        bool  any_location_discovered{ false };
        std::unordered_set<location_id>  covered_locations{};
        std::unordered_map<location_id, std::unordered_set<branching_node*> >  uncovered_locations{};
    };

    struct  primary_coverage_target_branchings
    {
        primary_coverage_target_branchings(
                std::function<bool(location_id)> const&  is_covered_,
                std::function<branching_node*(location_id)> const&  iid_pivot_with_lowest_abs_value_,
                performance_statistics*  statistics_ptr_
                );

        void  collect_loop_heads_along_path_to_node(branching_node* const  end_node);
        void  process_potential_coverage_target(std::pair<branching_node*, bool> const&  node_and_flag);
        void  erase(branching_node*  node);

        bool  empty() const;
        void  clear();

        void  do_cleanup();
        branching_node*  get_best(natural_32_bit  max_input_width);

    private:
        branching_node*  get_best(std::unordered_map<branching_node*, bool>&  targets, natural_32_bit  max_input_width);

        std::unordered_set<branching_node*>  loop_heads;        // Priority #1 (the highest)
        std::unordered_map<branching_node*, bool>  sensitive;   // Priority #2
        std::unordered_map<branching_node*, bool>  untouched;   // Priority #3
        std::unordered_map<location_id, std::pair<branching_node*, bool> >  iid_twins;   // Priority #4
        std::function<bool(location_id)>  is_covered;
        std::function<branching_node*(location_id)>  iid_pivot_with_lowest_abs_value;
        performance_statistics*  statistics;
    };

    struct  hit_count_per_direction
    {
        hit_count_per_direction() : hit_count{ 0U, 0U } {}
        hit_count_per_direction(natural_32_bit const  left, natural_32_bit const  right) : hit_count{ left, right } {}
        natural_32_bit  operator[](bool const  direction) const { return hit_count[direction ? 1 : 0]; }
        natural_32_bit&  operator[](bool const  direction) { return hit_count[direction ? 1 : 0]; }
        natural_32_bit  total() const { return hit_count[0] + hit_count[1]; }
        natural_32_bit  hit_count[2];
    };

    struct  histogram_of_hit_counts_per_direction
    {
        using  hit_counts_map = std::unordered_map<location_id::id_type, hit_count_per_direction>;
        using  pointer_type = std::shared_ptr<histogram_of_hit_counts_per_direction>;

        static inline pointer_type  create(pointer_type  predecessor_ptr_)
        { return std::make_shared<histogram_of_hit_counts_per_direction>(predecessor_ptr_); }

        histogram_of_hit_counts_per_direction(pointer_type const  ptr) : hit_counts{}, predecessor_ptr{ ptr } {}
        hit_counts_map const&  local_hit_counts() const { return hit_counts; }
        hit_counts_map&  local_hit_counts_ref() { return hit_counts; }
        pointer_type  get_predecessor() const { return predecessor_ptr; }
        void  merge(hit_counts_map&  result) const { merge(this, nullptr, result); }
    private:
        static void  merge(
                histogram_of_hit_counts_per_direction const*  histogram,
                histogram_of_hit_counts_per_direction const* const  end,
                hit_counts_map&  result
                );
        hit_counts_map  hit_counts;
        pointer_type  predecessor_ptr;
    };

    struct  probability_generator
    {
        virtual ~probability_generator() {}
        virtual float_32_bit  next() = 0;
    };

    struct  probability_generator_random_uniform : public probability_generator
    {
        probability_generator_random_uniform(random_generator_for_natural_32_bit&  random_generator) : generator{ random_generator } {}
        float_32_bit  next() override { return get_random_float_32_bit_in_range(0.0f, 1.0f, generator); }
    private:
        random_generator_for_natural_32_bit&  generator;
    };

    struct  probability_generator_all_then_all : public probability_generator
    {
        probability_generator_all_then_all(float_32_bit  false_direction_probability_, natural_32_bit  total_num_samples_, bool  first_direction_);
        float_32_bit  next() override;
    private:
        natural_32_bit  samples_total[2];
        natural_32_bit  samples_consumed[2];
        bool  direction;
    };

    using  histogram_of_false_direction_probabilities = std::unordered_map<location_id::id_type, float_32_bit>;
    using  probability_generators_for_locations = std::unordered_map<location_id::id_type, std::shared_ptr<probability_generator> >;

    struct  loop_boundary_props
    {
        branching_node*  entry;
        branching_node*  exit;
        branching_node*  successor;
    };

    struct  iid_pivot_props
    {
        std::vector<branching_node*>  loop_boundaries;
        std::unordered_set<location_id>  pure_loop_bodies;
        histogram_of_hit_counts_per_direction::pointer_type  histogram_ptr;
        mutable random_generator_for_natural_32_bit  generator_for_start_node_selection;
        mutable random_generator_for_natural_32_bit  generator_for_monte_carlo;
    };

    struct  iid_location_props
    {
        std::unordered_map<branching_node*, iid_pivot_props>  pivots;
        branching_node*  pivot_with_lowest_abs_value{ nullptr };
        mutable random_generator_for_natural_32_bit  generator_for_pivot_selection;
    };

    static void  update_close_flags_from(branching_node*  node);

    static std::vector<natural_32_bit> const&  get_input_width_classes();
    static std::unordered_set<natural_32_bit> const&  get_input_width_classes_set();
    static natural_32_bit  get_input_width_class(natural_32_bit  num_input_bytes);
    static natural_32_bit  get_input_width_class_index(natural_32_bit  num_input_bytes);

    static void  detect_loops_along_path_to_node(
            branching_node* const  end_node,
            std::unordered_map<location_id, std::unordered_set<location_id> >&  loop_heads_to_bodies,
            std::vector<loop_boundary_props>*  loops
            );
    static void  compute_loop_boundaries(
            std::vector<loop_boundary_props> const&  loops,
            std::vector<branching_node*>&  loop_boundaries
            );

    static std::unordered_map<branching_node*, iid_pivot_props>::const_iterator  select_best_iid_pivot(
            std::unordered_map<branching_node*, iid_pivot_props> const&  pivots,
            natural_32_bit  max_input_width,
            random_generator_for_natural_32_bit&  random_generator,
            float_32_bit const  LIMIT_STEP = 0.5f
            );

    static void  compute_histogram_of_false_direction_probabilities(
            natural_32_bit const  input_width,
            std::unordered_set<location_id> const&  pure_loop_bodies,
            std::unordered_map<branching_node*, iid_pivot_props> const&  pivots,
            histogram_of_false_direction_probabilities&  histogram
            );

    static branching_node*  select_start_node_for_monte_carlo_search(
            std::vector<branching_node*> const&  loop_boundaries,
            random_generator_for_natural_32_bit&  random_generator,
            float_32_bit  LIMIT_STEP = 0.5f,
            branching_node*  fallback_node = nullptr
            );

    static std::shared_ptr<probability_generator_random_uniform>  compute_probability_generators_for_locations(
            histogram_of_false_direction_probabilities const&  probabilities,
            histogram_of_hit_counts_per_direction::hit_counts_map const&  hit_counts,
            std::unordered_set<location_id> const&  pure_loop_bodies,
            probability_generators_for_locations&  generators,
            random_generator_for_natural_32_bit&  generator_for_generator_selection,
            random_generator_for_natural_32_bit&  generator_for_generators
            );

    static branching_node*  monte_carlo_search(
            branching_node*  root,
            histogram_of_false_direction_probabilities const&  histogram,
            probability_generators_for_locations const&  generators,
            probability_generator_random_uniform&  location_miss_generator
            );
    static std::pair<branching_node*, bool>  monte_carlo_backward_search(
            branching_node* const  start_node,
            branching_node* const  end_node,
            histogram_of_false_direction_probabilities const&  histogram,
            probability_generators_for_locations const&  generators,
            probability_generator_random_uniform&  location_miss_generator
            );
    static branching_node*  monte_carlo_step(
            branching_node* const  pivot,
            histogram_of_false_direction_probabilities const&  histogram,
            probability_generators_for_locations const&  generators,
            probability_generator_random_uniform&  location_miss_generator
            );

    void  generate_next_input(vecb&  stdin_bits);
    execution_record::execution_flags  process_execution_results();

    void  do_cleanup();
    void  collect_iid_pivots_from_sensitivity_results();
    void  select_next_state();
    branching_node*  select_iid_coverage_target() const;

    void  remove_leaf_branching_node(branching_node*  node);
    bool  apply_coverage_failures_with_hope();

    termination_info termination_props;

    natural_32_bit  num_driver_executions;
    std::chrono::steady_clock::time_point  time_point_start;
    std::chrono::steady_clock::time_point  time_point_current;

    branching_node*  entry_branching;
    std::unordered_set<branching_node*>  leaf_branchings;

    std::unordered_set<location_id>  covered_branchings;
    std::unordered_set<branching_location_and_direction>  uncovered_branchings;
    std::unordered_set<location_id>  branchings_to_crashes;

    primary_coverage_target_branchings  primary_coverage_targets;
    std::unordered_map<location_id, iid_location_props>  iid_pivots;

    std::unordered_set<branching_node*>  coverage_failures_with_hope;

    STATE  state;
    sensitivity_analysis  sensitivity;
    typed_minimization_analysis  typed_minimization;
    minimization_analysis  minimization;
    bitshare_analysis  bitshare;

    natural_32_bit  max_input_width;

    mutable random_generator_for_natural_32_bit  generator_for_iid_location_selection;
    mutable random_generator_for_natural_32_bit  generator_for_iid_approach_selection;
    mutable random_generator_for_natural_32_bit  generator_for_generator_selection;

    mutable performance_statistics  statistics;
};


}

#endif
