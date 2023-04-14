#ifndef IOMODELS_IOMANAGER_HPP_INCLUDED
#   define IOMODELS_IOMANAGER_HPP_INCLUDED

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


using namespace instrumentation;


struct  iomanager
{
    struct  configuration
    {
        natural_32_bit  max_trace_length{ 10000 };
        natural_8_bit  max_stack_size{ 25 };
        stdin_base::byte_count_type  max_stdin_bytes{ 1800 }; // Standard page: 60 * 30 chars.
        std::string  stdin_model_name{ "stdin_replay_bytes_then_repeat_85" };
        std::string  stdout_model_name{ "stdout_void" };
    };

    enum TERMINATION_TYPE
    {
        NORMAL                          = 0,    // Execution of benchmark's code finished normally.
        CRASH                           = 1,    // Benchmark's code crashed, e.g. division by zero, access outside allocated memory.
        BOUNDARY_CONDITION_VIOLATION    = 2,    // Benchmark's execution violated some of our boundaries; e.g. trace is too long,
                                                // stack has too many records, too many bits were read from stdin.
    };

    static iomanager&  instance();

    configuration const&  get_config() const { return config; }
    void  set_config(configuration const&  cfg);

    TERMINATION_TYPE  get_termination() const { return termination; }
    void  set_termination(TERMINATION_TYPE const  type) { termination = type; }
    void  save_termination(connection::message&  ostr) const;
    void  load_termination(connection::message&  istr);

    void  crash(natural_32_bit const  loc_id);

    std::vector<branching_coverage_info> const&  get_trace() const { return trace; }
    void  clear_trace();
    void  save_trace(connection::message&  ostr) const;
    void  load_trace(connection::message&  istr);
    void  branching(branching_coverage_info const&  info);
    void  clear_br_instr_trace();
    void  save_br_instr_trace(connection::message&  ostr) const;
    void  load_br_instr_trace(connection::message&  istr);
    void  br_instr(br_instr_coverage_info const&  info);
    void  call_begin(natural_32_bit  id);
    void  call_end(natural_32_bit  id);

    static std::unordered_map<std::string, std::function<stdin_base_ptr(stdin_base::byte_count_type)> > const&  get_stdin_models_map();
    stdin_base_ptr  get_stdin() const;
    void  clear_stdin();
    void  save_stdin(connection::message&  ostr) const;
    void  load_stdin(connection::message&  istr);
    void  read_stdin(location_id const  id, natural_8_bit* ptr, natural_8_bit const  count);

    static std::unordered_map<std::string, std::function<stdout_base_ptr()> > const&  get_stdout_models_map();
    stdout_base_ptr  get_stdout() const;
    void  clear_stdout();
    void  save_stdout(connection::message&  ostr) const;
    void  load_stdout(connection::message&  istr);
    void  write_stdout(location_id const  id, natural_8_bit const* ptr, natural_8_bit const  count);

private:
    iomanager();

    configuration  config;
    TERMINATION_TYPE  termination;
    std::vector<branching_coverage_info>  trace;
    std::vector<br_instr_coverage_info>  br_instr_trace;
    std::vector<natural_32_bit>  context_hashes;
    std::unordered_set<natural_32_bit>  locations;
    mutable stdin_base_ptr  stdin_ptr;
    mutable stdout_base_ptr  stdout_ptr;
};


}

#endif
