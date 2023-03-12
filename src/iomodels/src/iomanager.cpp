#include <iomodels/iomanager.hpp>
#include <utility/hash_combine.hpp>
#include <utility/assumptions.hpp>
#include <iostream>

namespace  iomodels {


iomanager::iomanager()
    : trace()
    , br_instr_trace()
    , context_hashes{ 0U }
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
    context_hashes.clear();
    context_hashes.push_back(0U);
}

void  iomanager::clear_br_instr_trace()
{
    br_instr_trace.clear();
}


void  iomanager::save_br_instr_trace(connection::message&  ostr) const 
{
    ostr << (natural_32_bit)br_instr_trace.size();
    for (br_instr_coverage_info const&  info : br_instr_trace) 
    {
        ostr << info.br_instr_id << info.covered_branch;
    }
}


void  iomanager::load_br_instr_trace(connection::message&  istr) 
{
    natural_32_bit  n;
    istr >> n;
    for (natural_32_bit i = 0; i < n; ++i)
    {
        br_instr_coverage_info  info(invalid_location_id());
        istr >> info.br_instr_id;
        istr >> info.covered_branch;
        br_instr_trace.push_back(info);
    }
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
    trace.back().branching_id.context_hash = context_hashes.back();
    trace.back().idx_to_br_instr = br_instr_trace.size();
}


void iomanager::br_instr(instrumentation::br_instr_coverage_info const&  info)
{
    if (!read_input) {
        return;
    }
    br_instr_trace.push_back(info);
}


void  iomanager::call_begin(natural_32_bit  id)
{
    ::hash_combine(id, context_hashes.back());
    context_hashes.push_back(id);
}


void  iomanager::call_end(natural_32_bit const  id)
{
    ASSUMPTION(
        context_hashes.size() > 1 &&
        [this](natural_32_bit  id) -> bool {
            ::hash_combine(id, context_hashes.at(context_hashes.size()-2));
            return id == context_hashes.back();
        }(id)
        );
    context_hashes.pop_back();
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
