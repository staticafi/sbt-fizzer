#ifndef IOMODELS_IOMANAGER_HPP_INCLUDED
#   define IOMODELS_IOMANAGER_HPP_INCLUDED

#   include <iomodels/stdin_base.hpp>
#   include <iomodels/stdout_base.hpp>
#   include <connection/medium.hpp>
#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/basic_numeric_types.hpp>
#   include <vector>

namespace  iomodels {


using namespace instrumentation;


struct  iomanager
{
    static iomanager&  instance();

    std::vector<branching_coverage_info> const&  get_trace() const { return trace; }
    stdin_base_ptr  get_stdin() const { return stdin_ptr; }
    stdout_base_ptr  get_stdout() const { return stdout_ptr; }

    void  clear_trace();
    void  save_trace(connection::medium&  ostr) const;
    void  load_trace(connection::medium&  istr);
    void  branching(branching_coverage_info const&  info);

    void  set_stdin(stdin_base_ptr  stdin_ptr_);
    void  clear_stdin();
    void  save_stdin(connection::medium&  ostr) const;
    void  load_stdin(connection::medium&  istr);
    void  read_stdin(location_id const  id, natural_8_bit* ptr, natural_8_bit const  count);

    void  set_stdout(stdout_base_ptr  stdout_ptr_);
    void  clear_stdout();
    void  save_stdout(connection::medium&  ostr) const;
    void  load_stdout(connection::medium&  istr);
    void  write_stdout(location_id const  id, natural_8_bit const* ptr, natural_8_bit const  count);

private:
    iomanager();

    std::vector<branching_coverage_info>  trace;
    stdin_base_ptr  stdin_ptr;
    stdout_base_ptr  stdout_ptr;
};


}

#endif
