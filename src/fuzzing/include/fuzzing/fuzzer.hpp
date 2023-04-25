#ifndef FUZZING_FUZZER_HPP_INCLUDED
#   define FUZZING_FUZZER_HPP_INCLUDED

#   include <fuzzing/termination_info.hpp>
#   include <fuzzing/sensitivity_analysis.hpp>
#   include <fuzzing/minimization_analysis.hpp>
#   include <fuzzing/jetklee_analysis.hpp>
#   include <fuzzing/execution_record.hpp>
#   include <fuzzing/analysis_statistics.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/math.hpp>
#   include <utility/std_pair_hash.hpp>
#   include <connection/kleeient_connector.hpp>
#   include <string>
#   include <unordered_set>
#   include <unordered_map>
#   include <set>
#   include <chrono>
#   include <memory>
#   include <limits>

namespace  fuzzing {


using namespace instrumentation;


struct  fuzzer final
{
    enum jetklee_usage
    {
        ALWAYS,
        NEVER,
        HEURISTIC
    };

    struct  performance_statistics
    {
        std::size_t  leaf_nodes_created{ 0 };
        std::size_t  leaf_nodes_destroyed{ 0 };
        std::size_t  nodes_created{ 0 };
        std::size_t  nodes_destroyed{ 0 };
        std::size_t  max_leaf_nodes{ 0 };
        std::size_t  longest_branch{ 0 };
        std::size_t  traces_to_crash_total{ 0 };
        std::size_t  traces_to_crash_recorded{ 0 };
    };

    explicit fuzzer(termination_info const&  info,
                    std::unique_ptr<connection::kleeient_connector> kleeient_connector,
                    bool  debug_mode_ = false,
                    bool  capture_analysis_stats = false,
                    jetklee_usage  jetklee_usage_policy = HEURISTIC);
    ~fuzzer();

    void  terminate();

    termination_info const& get_termination_info() const { return termination_props; }

    long  num_remaining_driver_executions() const { return (long)termination_props.max_driver_executions - (long)num_driver_executions; }
    long  num_remaining_seconds() const { return (long)termination_props.max_fuzzing_seconds - get_elapsed_seconds(); }

    natural_32_bit  get_performed_driver_executions() const { return num_driver_executions; }
    long  get_elapsed_seconds() const { return (long)std::chrono::duration_cast<std::chrono::seconds>(time_point_current - time_point_start).count(); }

    std::unordered_set<location_id> const&  get_covered_branchings() const { return covered_branchings; }
    std::unordered_set<branching_location_and_direction> const&  get_uncovered_branchings() const { return uncovered_branchings; }

    bool  can_make_progress() const { return state != FINISHED; }

    std::string  round_begin();
    bool  round_end(execution_record&  record);

    sensitivity_analysis::performance_statistics const&  get_sensitivity_statistics() const { return sensitivity.get_statistics(); }
    minimization_analysis::performance_statistics const&  get_minimization_statistics() const { return minimization.get_statistics(); }
    jetklee_analysis::performance_statistics const&  get_jetklee_statistics() const { return jetklee.get_statistics(); }
    performance_statistics const&  get_fuzzer_statistics() const { return statistics; }
    analysis_statistics const&  get_analysis_statistics() const { return analysis_stats; }

    std::unordered_map<std::string, std::string> const&  get_debug_data() const { return debug_data; }

private:

    enum STATE
    {
        STARTUP,
        SENSITIVITY,
        MINIMIZATION,
        JETKLEE_QUERY,
        FINISHED
    };

    struct  leaf_branching_construction_props
    {
        branching_node*  leaf{ nullptr };
        branching_node*  diverging_node{ nullptr };
        branching_node*  frontier_node{ nullptr };
        bool  any_location_discovered{ false };
        std::unordered_set<location_id>  covered_locations{};
        std::unordered_map<location_id, std::unordered_set<branching_node*> >  uncovered_locations{};
    };

    struct  leaf_branching_processing_props
    {
        std::unordered_map<location_id, std::unordered_set<branching_node*> >  uncovered_branchings {};
        branching_node*  frontier_branching{ nullptr };
    };

    struct  iid_frontier_record
    {
        bool  operator<(iid_frontier_record const&  other) const;
        branching_node*  iid_node;
        branching_node*  node;
        natural_32_bit  distance;
        bool  forward;
    };

    void  debug_save_branching_tree(std::string const&  stage_name) const;

    void  generate_next_input(vecb&  stdin_bits);
    execution_record::execution_flags  process_execution_results();

    void  do_cleanup();
    void  remove_leaf_branching_node(branching_node*  node);

    void  select_next_state();

    bool  use_jetklee(branching_node* node);

    termination_info termination_props;

    natural_32_bit  num_driver_executions;
    std::chrono::steady_clock::time_point  time_point_start;
    std::chrono::steady_clock::time_point  time_point_current;

    branching_node*  entry_branching;
    std::unordered_map<branching_node*, leaf_branching_processing_props>  leaf_branchings;

    std::unordered_set<location_id>  covered_branchings;
    std::unordered_set<branching_location_and_direction>  uncovered_branchings;
    std::unordered_set<location_id>  branchings_to_crashes;

    std::unordered_set<location_id>  did_branchings;
    std::unordered_map<location_id, std::unordered_map<location_id, natural_32_bit> >  iid_regions;
    std::unordered_set<branching_node*>  iid_frontier_sources;
    std::multiset<iid_frontier_record>  iid_frontier;

    STATE  state;
    sensitivity_analysis  sensitivity;
    minimization_analysis  minimization;
    jetklee_analysis  jetklee;

    performance_statistics  statistics;
    analysis_statistics analysis_stats;

    bool  debug_mode;
    bool  capture_analysis_stats;
    jetklee_usage  jetklee_usage_policy;
    mutable std::unordered_map<std::string, std::string>  debug_data;
};


}

#endif
