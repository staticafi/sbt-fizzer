#ifndef FUZZING_PROGRESS_RECORDER_HPP_INCLUDED
#   define FUZZING_PROGRESS_RECORDER_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>
#   include <unordered_set>
#   include <string>
#   include <filesystem>

namespace  fuzzing {


struct  progress_recorder
{
    static progress_recorder& instance();

    void  start(std::filesystem::path const&  output_dir_);
    void  stop();

    bool  is_started() const { return started; }

    void  on_sensitivity_start() { on_analysis_start(SENSITIVITY); }
    void  on_sensitivity_stop() { on_analysis_stop(); }

    void  on_minimization_start() { on_analysis_start(MINIMIZATION); }
    void  on_minimization_stop() { on_analysis_stop(); }

    void  on_bitshare_start() { on_analysis_start(BITSHARE); }
    void  on_bitshare_stop() { on_analysis_stop(); }

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

    progress_recorder();

    progress_recorder(progress_recorder const&) = delete;
    progress_recorder(progress_recorder&&) = delete;
    progress_recorder& operator=(progress_recorder const&) const = delete;
    progress_recorder& operator=(progress_recorder&&) const = delete;

    void  on_analysis_start(ANALYSIS a);
    void  on_analysis_stop();

    static std::string const&  analysis_name(ANALYSIS a);

    bool  started;
    std::filesystem::path  output_dir;

    ANALYSIS  analysis;
    natural_32_bit  counter_analysis;
    natural_32_bit  counter_results;
    natural_32_bit  num_bytes;
};


inline progress_recorder&  recorder() { return progress_recorder::instance(); }


}

#endif
