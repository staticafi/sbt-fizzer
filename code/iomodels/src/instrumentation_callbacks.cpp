#include <iomodels/instrumentation_callbacks.hpp>
#include <iomodels/iomanager.hpp>

namespace  iomodels {

    
void  on_branching(instrumentation::branching_coverage_info const&  info)
{
    iomanager::instance().branching(info);
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
