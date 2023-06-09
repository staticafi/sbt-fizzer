#ifndef FUZZING_PROGRESS_RECORDER_HPP_INCLUDED
#   define FUZZING_PROGRESS_RECORDER_HPP_INCLUDED

#   include <fuzzing/branching_node.hpp>
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
    static progress_recorder& instance();

    void  start(std::filesystem::path const&  path_to_client_, std::filesystem::path const&  output_dir_);
    void  stop();

    bool  is_started() const { return started; }

    void  on_sensitivity_start(branching_node* const  node_ptr);
    void  on_sensitivity_stop();

    void  on_minimization_start(branching_node* const  node_ptr, vecu32 const&  bit_translation, stdin_bits_pointer  bits_ptr);
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
    void  on_minimization_stop();

    void  on_bitshare_start(branching_node* const  node_ptr);
    void  on_bitshare_stop();

    void  on_input_generated();
    void  on_execution_results_available();

private:

    enum ANALYSIS
    {
        NONE            = 0,
        SENSITIVITY     = 1,
        MINIMIZATION    = 2,
        BITSHARE        = 3
    };

    struct  analysis_common_info
    {
        virtual ~analysis_common_info() = default;
        virtual void  save_info(std::ostream&  ostr) const {}
        void  save() const;

        branching_node*  node{ nullptr };
        std::filesystem::path  analysis_dir{};
    };

    struct  sensitivity_progress_info : public analysis_common_info
    {
        void  save_info(std::ostream&  ostr) const override;
    };

    struct  minimization_progress_info : public analysis_common_info
    {
        using STAGE = minimization_analysis::gradient_descent_state::STAGE;

        struct  stage_change_info
        {
            natural_32_bit  trace_index;
            natural_32_bit  cache_hit_index;
            STAGE stage;
        };

        struct  execution_cache_hits_info
        {
            natural_32_bit  trace_index;
            std::size_t  bits_hash;
        };

        void  save_info(std::ostream&  ostr) const override;

        stdin_bits_pointer  bits_ptr{ nullptr };
        vecu32  bit_translation{};
        std::vector<stage_change_info>  stage_changes{};
        std::vector<execution_cache_hits_info>  execution_cache_hits{};
    };

    struct  bitshare_progress_info : public analysis_common_info
    {
        void  save_info(std::ostream&  ostr) const override;
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
    minimization_progress_info  minimization;
    bitshare_progress_info  bitshare;
    natural_32_bit  counter_analysis;
    natural_32_bit  counter_results;
    natural_32_bit  num_bytes;
};


inline progress_recorder&  recorder() { return progress_recorder::instance(); }


}

#endif
