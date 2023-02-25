#include <iomodels/instrumentation_callbacks.hpp>
#include <iomodels/iomanager.hpp>

namespace  iomodels {

    
void  on_branching(instrumentation::branching_coverage_info const&  info)
{
    iomanager::instance().branching(info);
}

void  on_br_instr(instrumentation::br_instr_coverage_info const&  info)
{
    iomanager::instance().br_instr(info);
}


void  on_call_begin(natural_32_bit const  id)
{
    iomanager::instance().call_begin(id);
}


void  on_call_end(natural_32_bit const  id)
{
    iomanager::instance().call_end(id);
}


void  on_read_stdin(instrumentation::location_id const  id, natural_8_bit* ptr, natural_8_bit const  count)
{
    iomanager::instance().read_stdin(id, ptr, count);
}


void  on_write_stdout(instrumentation::location_id const  id, natural_8_bit const* ptr, natural_8_bit const  count)
{
    iomanager::instance().write_stdout(id, ptr, count);
}


}
