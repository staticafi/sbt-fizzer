#ifndef IOMODELS_IOMANAGER_HPP_INCLUDED
#   define IOMODELS_IOMANAGER_HPP_INCLUDED

#   include <iomodels/stdin_base.hpp>
#   include <iomodels/stdout_base.hpp>
#   include <connection/message.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/basic_numeric_types.hpp>
#   include <vector>

namespace  iomodels {


using namespace instrumentation;
using connection::message_type;


struct  trace_max_size_reached_exception: public std::runtime_error
{
    explicit trace_max_size_reached_exception(char const* const message): std::runtime_error(message) {}
};


struct  iomanager
{
    static iomanager&  instance();

    std::vector<branching_coverage_info> const&  get_trace() const { return trace; }
    std::size_t  get_trace_max_size() const { return trace_max_size; }
    stdin_base_ptr  get_stdin() const { return stdin_ptr; }
    stdout_base_ptr  get_stdout() const { return stdout_ptr; }

    void  clear_trace();
    void  save_trace(connection::message&  ostr) const;
    void  load_trace(connection::message&  istr);
    void  set_trace_max_size(std::size_t max_size);
    void  branching(branching_coverage_info const&  info);
    void  clear_br_instr_trace();
    void  save_br_instr_trace(connection::message&  ostr) const;
    void  load_br_instr_trace(connection::message&  istr);
    void  br_instr(br_instr_coverage_info const&  info);
    void  call_begin(natural_32_bit  id);
    void  call_end(natural_32_bit  id);

    void  set_stdin(stdin_base_ptr  stdin_ptr_);
    void  clear_stdin();
    void  save_stdin(connection::message&  ostr) const;
    void  load_stdin(connection::message&  istr);
    void  read_stdin(location_id const  id, natural_8_bit* ptr, natural_8_bit const  count);

    void  set_stdout(stdout_base_ptr  stdout_ptr_);
    void  clear_stdout();
    void  save_stdout(connection::message&  ostr) const;
    void  load_stdout(connection::message&  istr);
    void  write_stdout(location_id const  id, natural_8_bit const* ptr, natural_8_bit const  count);

private:
    iomanager();

    std::vector<branching_coverage_info>  trace;
    std::vector<br_instr_coverage_info>  br_instr_trace;
    std::vector<natural_32_bit>  context_hashes;
    stdin_base_ptr  stdin_ptr;
    stdout_base_ptr  stdout_ptr;
    std::size_t trace_max_size;
    bool read_input;
public: 
    message_type received_message_type;
};


}

#endif
