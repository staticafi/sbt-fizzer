#ifndef IOMODELS_IOMANAGER_HPP_INCLUDED
#   define IOMODELS_IOMANAGER_HPP_INCLUDED

#   include <iomodels/configuration.hpp>
#   include <instrumentation/target_termination.hpp>
#   include <iomodels/stdin_base.hpp>
#   include <iomodels/stdout_base.hpp>
#   include <connection/message.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/basic_numeric_types.hpp>
#   include <vector>
#   include <string>
#   include <unordered_map>
#   include <unordered_set>
#   include <functional>

namespace  iomodels {


struct  iomanager
{
    static iomanager&  instance();

    configuration const&  get_config() const { return config; }
    void  set_config(configuration const&  cfg);

    instrumentation::target_termination  get_termination() const { return termination; }

    template <typename Medium>
    void  load_results(Medium& src);

    template <typename Medium>
    bool  load_trace_record(Medium& src);

    template <typename Medium>
    bool  load_br_instr_trace_record(Medium& src);

    std::vector<instrumentation::branching_coverage_info> const&  get_trace() const { return trace; }
    void  clear_trace();
    std::vector<instrumentation::br_instr_coverage_info> const&  get_br_instr_trace() const { return br_instr_trace; }
    void  clear_br_instr_trace();

    stdin_base*  get_stdin() const;
    stdout_base*  get_stdout() const;

    stdin_base_ptr  clone_stdin() const;
    stdout_base_ptr  clone_stdout() const;

private:
    iomanager();

    configuration config;
    instrumentation::target_termination  termination;
    std::vector<instrumentation::branching_coverage_info>  trace;
    std::vector<instrumentation::br_instr_coverage_info>  br_instr_trace;
    mutable stdin_base_ptr  stdin_ptr;
    mutable stdout_base_ptr  stdout_ptr;
};


}

#endif
