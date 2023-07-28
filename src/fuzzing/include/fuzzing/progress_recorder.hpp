#ifndef FUZZING_PROGRESS_RECORDER_HPP_INCLUDED
#   define FUZZING_PROGRESS_RECORDER_HPP_INCLUDED

#   include <fuzzing/branching_node.hpp>
#   include <fuzzing/typed_minimization_analysis.hpp>
#   include <fuzzing/minimization_analysis.hpp>
#   include <utility/basic_numeric_types.hpp>
#   include <unordered_set>
#   include <string>
#   include <filesystem>
#   include <memory>
#   include <iosfwd>

namespace  fuzzing {


struct  progress_recorder
{
    enum STOP_ATTRIBUTE
    {
        INSTANT = 0,
        EARLY = 1,
        REGULAR = 2
    };

    static progress_recorder& instance();

    void  start(std::filesystem::path const&  path_to_client_, std::filesystem::path const&  output_dir_);
    void  stop();

    bool  is_started() const { return started; }

    void  on_sensitivity_start(branching_node* const  node_ptr);
    void  on_sensitivity_stop(STOP_ATTRIBUTE  attribute);

    void  on_typed_minimization_start(
            branching_node* const  node_ptr,
            std::vector<typed_minimization_analysis::mapping_to_input_bits> const&  from_variables_to_input,
            std::vector<type_of_input_bits> const& types_of_variables,
            stdin_bits_and_types_pointer  bits_and_types
            );
    void  on_typed_minimization_execution_results_available(
            typed_minimization_analysis::PROGRESS_STAGE  progress_stage,
            std::vector<typed_minimization_analysis::value_of_variable> const&  variable_values,
            branching_function_value_type  function_value,
            std::size_t  variables_hash
            );
    void  on_typed_minimization_execution_results_cache_hit(
            typed_minimization_analysis::PROGRESS_STAGE  progress_stage,
            std::size_t  variables_hash
            );
    void  on_typed_minimization_stop(STOP_ATTRIBUTE  attribute);

    void  on_minimization_start(branching_node* const  node_ptr, vecu32 const&  bit_translation, stdin_bits_and_types_pointer  bits_and_types);
    void  on_minimization_gradient_step();
    void  on_minimization_execution_results_available(
            minimization_analysis::gradient_descent_state::STAGE stage,
            vecb const&  bits,
            std::size_t  bits_hash
            );
    void  on_minimization_execution_results_cache_hit(
            minimization_analysis::gradient_descent_state::STAGE stage,
            std::size_t  bits_hash
            );
    void  on_minimization_stop(STOP_ATTRIBUTE  attribute);

    void  on_bitshare_start(branching_node* const  node_ptr);
    void  on_bitshare_stop(STOP_ATTRIBUTE  attribute);

    void  on_input_generated();
    void  on_trace_mapped_to_tree(branching_node*  leaf_);
    void  on_execution_results_available();

    void  on_strategy_turn_primary_loop_head();
    void  on_strategy_turn_primary_sensitive();
    void  on_strategy_turn_primary_untouched();
    void  on_strategy_turn_primary_iid_twins();
    void  on_strategy_turn_monte_carlo();
    void  on_strategy_turn_monte_carlo_backward();
    void  on_post_node_closed(branching_node*  node);
    void  flush_post_data();

private:

    enum ANALYSIS
    {
        NONE                = 0,
        SENSITIVITY         = 1,
        TYPED_MINIMIZATION  = 2,
        MINIMIZATION        = 3,
        BITSHARE            = 4
    };

    struct  analysis_common_info
    {
        virtual ~analysis_common_info() = default;
        virtual natural_32_bit  get_num_coverage_failure_resets() const { return node->num_coverage_failure_resets; }
        virtual void  save_info(std::ostream&  ostr) const {}
        void  save() const;

        branching_node*  node{ nullptr };
        std::filesystem::path  analysis_dir{};
        STOP_ATTRIBUTE  stop_attribute{ REGULAR };
    };

    struct  sensitivity_progress_info : public analysis_common_info
    {
        natural_32_bit  get_num_coverage_failure_resets() const override;
        void  save_info(std::ostream&  ostr) const override;
    };

    struct  typed_minimization_progress_info : public analysis_common_info
    {
        using PROGRESS_STAGE = typed_minimization_analysis::PROGRESS_STAGE;

        struct  execution_cache_hits_info
        {
            natural_32_bit  trace_index;
            std::size_t  variables_hash;
            PROGRESS_STAGE  progress_stage;
        };

        void  save_info(std::ostream&  ostr) const override;

        stdin_bits_and_types_pointer  bits_and_types{ nullptr };
        std::vector<typed_minimization_analysis::mapping_to_input_bits>  from_variables_to_input{};
        std::vector<type_of_input_bits>  types_of_variables{};
        std::vector<execution_cache_hits_info>  execution_cache_hits{};
    };

    struct  minimization_progress_info : public analysis_common_info
    {
        using STAGE = minimization_analysis::gradient_descent_state::STAGE;

        struct  stage_change_info
        {
            integer_32_bit  index;
            STAGE stage;
        };

        struct  execution_cache_hits_info
        {
            natural_32_bit  trace_index;
            std::size_t  bits_hash;
        };

        void  save_info(std::ostream&  ostr) const override;

        stdin_bits_and_types_pointer  bits_and_types{ nullptr };
        vecu32  bit_translation{};
        std::vector<stage_change_info>  stage_changes{};
        std::vector<execution_cache_hits_info>  execution_cache_hits{};
    };

    struct  bitshare_progress_info : public analysis_common_info
    {
        void  save_info(std::ostream&  ostr) const override;
    };

    struct  post_analysis_data
    {
        enum STRATEGY
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
        void  on_node_closed(branching_node*  node);

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

    void  on_analysis_start(ANALYSIS a, analysis_common_info&  info, branching_node*  node_ptr);
    void  on_analysis_stop();

    std::unique_ptr<std::ofstream>  save_default_execution_results();

    static std::string const&  analysis_name(ANALYSIS a);

    bool  started;
    std::filesystem::path  output_dir;

    ANALYSIS  analysis;
    sensitivity_progress_info  sensitivity;
    typed_minimization_progress_info  typed_minimization;
    minimization_progress_info  minimization;
    bitshare_progress_info  bitshare;
    natural_32_bit  counter_analysis;
    natural_32_bit  counter_results;

    natural_32_bit  num_bytes;
    branching_node*  leaf;

    post_analysis_data  post_data;
};


inline progress_recorder&  recorder() { return progress_recorder::instance(); }


}

#endif
