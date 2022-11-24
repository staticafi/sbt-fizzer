#include <iomodels/iomanager.hpp>
#include <iostream>

namespace  iomodels {


iomanager::iomanager()
    : trace()
    , stdin_ptr(nullptr)
    , stdout_ptr(nullptr)
    , trace_max_size()
    , read_input(false)
{}


iomanager&  iomanager::instance()
{
    static iomanager  man;
    return man;
}



void  iomanager::clear_trace()
{
    trace.clear();
}


void  iomanager::save_trace(connection::message&  ostr) const
{
    ostr << (natural_32_bit)trace.size();
    for (branching_coverage_info const&  info : trace)
        ostr << info.branching_id
             << info.covered_branch
             << info.distance_to_uncovered_branch
             ;
}


void  iomanager::load_trace(connection::message&  istr)
{
    natural_32_bit  n;
    istr >> n;
    for (natural_32_bit  i = 0ULL; i < n; ++i)
    {
        branching_coverage_info  info(invalid_location_id());
        istr >> info.branching_id;
        istr >> info.covered_branch;
        istr >> info.distance_to_uncovered_branch;
        trace.push_back(info);
    }
}


void  iomanager::set_trace_max_size(std::size_t max_size) {
    trace_max_size = max_size;
}


void  iomanager::branching(instrumentation::branching_coverage_info const&  info)
{
    if (!read_input) {
        return;
    }
    if (trace.size() >= trace_max_size) {
        throw trace_max_size_reached_exception("Trace reached maximum allowed size");
    }
    trace.push_back(info);
}


void  iomanager::set_stdin(stdin_base_ptr const  stdin_ptr_)
{
    stdin_ptr = stdin_ptr_;
}


void  iomanager::clear_stdin()
{
    stdin_ptr->clear();
}


void  iomanager::save_stdin(connection::message&  ostr) const
{
    stdin_ptr->save(ostr);
}


void  iomanager::load_stdin(connection::message&  istr)
{
    stdin_ptr->load(istr);
}


void  iomanager::read_stdin(location_id const  id, natural_8_bit* ptr, natural_8_bit const  count)
{
    read_input = true;
    stdin_ptr->read(id, ptr, count);
}

void  iomanager::set_stdout(stdout_base_ptr  stdout_ptr_)
{
    stdout_ptr = stdout_ptr_;
}


void  iomanager::clear_stdout()
{
    stdout_ptr->clear();
}


void  iomanager::save_stdout(connection::message&  ostr) const
{
    stdout_ptr->save(ostr);
}


void  iomanager::load_stdout(connection::message&  istr)
{
    stdout_ptr->load(istr);
}


void  iomanager::write_stdout(location_id const  id, natural_8_bit const* ptr, natural_8_bit const  count)
{
    stdout_ptr->write(id, ptr, count);
}


}
