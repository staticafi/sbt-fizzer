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
#   include <array>
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
        std::size_t  longest_branch{ 0 };
        std::size_t  traces_to_crash{ 0 };
        std::size_t  traces_to_boundary_violation{ 0 };
        std::size_t  coverage_failure_resets{ 0 };
    };

    explicit fuzzer(termination_info const&  info, bool  debug_mode_ = false);
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
    bool  round_end(execution_record&  record);

    sensitivity_analysis::performance_statistics const&  get_sensitivity_statistics() const { return sensitivity.get_statistics(); }
    typed_minimization_analysis::performance_statistics const&  get_typed_minimization_statistics() const { return typed_minimization.get_statistics(); }
    minimization_analysis::performance_statistics const&  get_minimization_statistics() const { return minimization.get_statistics(); }
    bitshare_analysis::performance_statistics const&  get_bitshare_statistics() const { return bitshare.get_statistics(); }
    performance_statistics const&  get_fuzzer_statistics() const { return statistics; }

    std::unordered_map<std::string, std::string> const&  get_debug_data() const { return debug_data; }

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
                std::function<bool(location_id)> const&  is_iid_
                );

        void  process_potential_coverage_target(branching_node*  node);
        void  erase(branching_node*  node);

        bool  empty() const;
        void  clear();

        void  do_cleanup();
        branching_node*  get_best();

    private:
        static branching_node*  get_best(std::unordered_set<branching_node*> const&  targets);

        std::unordered_set<branching_node*>  sensitive; // Priority #1 (the highest)
        std::unordered_set<branching_node*>  untouched; // Priority #2
        std::unordered_set<branching_node*>  iid_twins; // Priority #3
        std::function<bool(location_id)>  is_covered;
        std::function<bool(location_id)>  is_iid;
    };

    struct  hit_count_per_direction
    {
        hit_count_per_direction() : hit_count{ 0U, 0U } {}
        hit_count_per_direction(natural_32_bit const  left, natural_32_bit const  right) : hit_count{ left, right } {}
        natural_32_bit  operator[](bool const  direction) const { return hit_count[direction ? 1 : 0]; }
        natural_32_bit&  operator[](bool const  direction) { return hit_count[direction ? 1 : 0]; }
        natural_32_bit  hit_count[2];
    };

    using  histogram_of_hit_counts_per_direction = std::unordered_map<location_id::id_type, hit_count_per_direction>;

    struct  iid_pivot_props
    {
        branching_node*  pivot;
        histogram_of_hit_counts_per_direction  histogram;
        mutable random_generator_for_natural_32_bit  random_generator;
    };

    static void  update_close_flags_from(branching_node*  node);
    static void  compute_hit_counts_histogram(branching_node const*  pivot, histogram_of_hit_counts_per_direction&  histogram);
    static branching_node*  monte_carlo_search(branching_node*  root, iid_pivot_props const&  props);

    void  debug_save_branching_tree(std::string const&  stage_name) const;

    void  generate_next_input(vecb&  stdin_bits);
    execution_record::execution_flags  process_execution_results();

    void  do_cleanup();
    void  select_next_state();

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
    std::unordered_map<location_id, std::unordered_map<natural_32_bit, std::unordered_map<branching_node*, iid_pivot_props> > >  iid_pivots;

    std::unordered_set<branching_node*>  coverage_failures_with_hope;

    STATE  state;
    sensitivity_analysis  sensitivity;
    typed_minimization_analysis  typed_minimization;
    minimization_analysis  minimization;
    bitshare_analysis  bitshare;

    random_generator_for_natural_32_bit  generator_iid_props_selection;

    performance_statistics  statistics;

    bool  debug_mode;
    mutable std::unordered_map<std::string, std::string>  debug_data;
};


}

#endif
