#ifndef FUZZING_PROGRESS_RECORDER_HPP_INCLUDED
#   define FUZZING_PROGRESS_RECORDER_HPP_INCLUDED

#   include <fuzzing/branching_node.hpp>
#   include <utility/basic_numeric_types.hpp>
#   include <unordered_set>
#   include <string>
#   include <filesystem>
#   include <memory>
#   include <iosfwd>

namespace  fuzzing {


struct  progress_recorder
{
    enum struct START
    {
        NONE    = 0,
        REGULAR = 1,
        RESUMED = 2
    };

    enum struct STOP
    {
        INSTANT     = 0,
        EARLY       = 1,
        REGULAR     = 2,
        INTERRUPTED = 3,
        FAILED      = 4
    };

    static progress_recorder& instance();

    void  start(std::filesystem::path const&  path_to_client_, std::filesystem::path const&  output_dir_);
    void  stop();

    bool  is_started() const { return started; }

    void  on_bitshare_start(branching_node const*  node_ptr, START attribute);
    void  on_bitshare_stop(STOP  attribute);

    void  on_local_search_start(branching_node const*  node_ptr, START attribute);
    void  on_local_search_stop(STOP  attribute);

    void  on_bitflip_start(branching_node const*  node_ptr, START attribute);
    void  on_bitflip_stop(STOP  attribute);

    void  on_taint_request_start(branching_node const*  node_ptr, START attribute);
    void  on_taint_request_stop(STOP  attribute);

    void  on_taint_response_start(branching_node const*  node_ptr, START attribute);
    void  on_taint_response_stop(STOP  attribute);

    void  on_input_generated();
    void  on_trace_mapped_to_tree(branching_node const*  leaf_);
    void  on_execution_results_available();

    void  on_strategy_turn_primary_loop_head();
    void  on_strategy_turn_primary_sensitive();
    void  on_strategy_turn_primary_untouched();
    void  on_strategy_turn_primary_iid_twins();
    void  on_strategy_turn_monte_carlo();
    void  on_strategy_turn_monte_carlo_backward();
    void  on_post_node_closed(branching_node const*  node);
    void  flush_post_data();

private:

    enum struct ANALYSIS
    {
        NONE            = 0,
        BITSHARE        = 1,
        LOCAL_SEARCH    = 2,
        BITFLIP         = 3,
        TAINT_REQUEST   = 4,
        TAINT_RESPONSE  = 5,
    };

    struct  analysis_common_info
    {
        virtual ~analysis_common_info() = default;
        virtual natural_32_bit  get_num_coverage_failure_resets() const { return node->get_num_coverage_failure_resets(); }
        virtual void  save_info(std::ostream&  ostr) const {}
        void  save() const;

        branching_node const*  node{ nullptr };
        std::filesystem::path  analysis_dir{};
        START  start_type{ START::NONE };
        STOP  stop_type{ STOP::REGULAR };
    };

    struct  bitshare_progress_info : public analysis_common_info
    {
        void  save_info(std::ostream&  ostr) const override;
    };

    struct  local_search_progress_info : public analysis_common_info
    {
        void  save_info(std::ostream&  ostr) const override;
    };

    struct  bitflip_progress_info : public analysis_common_info
    {
        void  save_info(std::ostream&  ostr) const override;
    };

    struct  taint_request_progress_info : public analysis_common_info
    {
        void  save_info(std::ostream&  ostr) const override;
    };

    struct  taint_response_progress_info : public analysis_common_info
    {
        void  save_info(std::ostream&  ostr) const override;
    };

    struct  post_analysis_data
    {
        enum struct STRATEGY
        {
            NONE                    = 0,
            PRIMARY_LOOP_HEAD       = 1,
            PRIMARY_SENSITIVE       = 2,
            PRIMARY_UNTOUCHED       = 3,
            PRIMARY_IID_TWINS       = 4,
            MONTE_CARLO             = 5,
            MONTE_CARLO_BACKWARD    = 6
        };

        post_analysis_data();

        void  on_strategy_changed(STRATEGY strategy_);
        void  on_node_closed(branching_node const*  node);

        void  set_output_dir(std::filesystem::path const&  dir);
        void  clear();
        bool  empty() const;
        void  save() const;

        std::filesystem::path  output_dir;
        STRATEGY  strategy;
        std::unordered_set<branching_node::guid_type>  closed_node_guids;
    };

    progress_recorder();

    progress_recorder(progress_recorder const&) = delete;
    progress_recorder(progress_recorder&&) = delete;
    progress_recorder& operator=(progress_recorder const&) const = delete;
    progress_recorder& operator=(progress_recorder&&) const = delete;

    void  on_analysis_start(ANALYSIS analysis_, analysis_common_info&  info, branching_node const*  node_ptr);
    void  on_analysis_stop();

    std::unique_ptr<std::ofstream>  save_default_execution_results();

    static std::string const&  analysis_name(ANALYSIS a);

    bool  started;

    std::filesystem::path  output_dir;
    std::string  program_name;

    ANALYSIS  analysis;
    bitshare_progress_info  bitshare;
    local_search_progress_info  local_search;
    bitflip_progress_info  bitflip;
    taint_request_progress_info  taint_request;
    taint_response_progress_info  taint_response;
    natural_32_bit  counter_analysis;
    natural_32_bit  counter_results;

    natural_32_bit  num_bytes;
    branching_node const*  leaf;

    post_analysis_data  post_data;
};


inline progress_recorder&  recorder() { return progress_recorder::instance(); }


}

#endif
