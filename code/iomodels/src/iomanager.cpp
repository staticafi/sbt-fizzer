#include <iomodels/iomanager.hpp>
#include <iostream>

namespace  iomodels {


iomanager::iomanager()
    : trace()
    , stdin_ptr(nullptr)
    , stdout_ptr(nullptr)
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


void  iomanager::save_trace(connection::medium&  ostr) const
{
    ostr << (natural_32_bit)trace.size();
    for (branching_coverage_info const&  info : trace)
        ostr << info.branching_id
             << info.covered_branch
             << info.distance_to_uncovered_branch
             ;
}


void  iomanager::load_trace(connection::medium&  istr)
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


void  iomanager::branching(instrumentation::branching_coverage_info const&  info)
{
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


void  iomanager::save_stdin(connection::medium&  ostr) const
{
    stdin_ptr->save(ostr);
}


void  iomanager::load_stdin(connection::medium&  istr)
{
    stdin_ptr->load(istr);
}


void  iomanager::read_stdin(location_id const  id, natural_8_bit* ptr, natural_8_bit const  count)
{
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


void  iomanager::save_stdout(connection::medium&  ostr) const
{
    stdout_ptr->save(ostr);
}


void  iomanager::load_stdout(connection::medium&  istr)
{
    stdout_ptr->load(istr);
}


void  iomanager::write_stdout(location_id const  id, natural_8_bit const* ptr, natural_8_bit const  count)
{
    stdout_ptr->write(id, ptr, count);
}


}