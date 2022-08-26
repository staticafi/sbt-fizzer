#ifndef IOMODELS_INSTRUMENTATION_CALLBACKS_HPP_INCLUDED
#   define IOMODELS_INSTRUMENTATION_CALLBACKS_HPP_INCLUDED

#   include <instrumentation/instrumentation_types.hpp>
#   include <utility/basic_numeric_types.hpp>

namespace  iomodels {


void  on_branching(instrumentation::branching_coverage_info const&  info);

void  on_read_stdin(instrumentation::location_id const  id, natural_8_bit* ptr, natural_8_bit const  count);
void  on_write_stdout(instrumentation::location_id const  id, natural_8_bit const* ptr, natural_8_bit const  count);


}

#endif
