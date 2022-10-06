#include <iomodels/stdout_void.hpp>

namespace  iomodels {


void  stdout_void::clear()
{
    // Nothing to do.
}


void  stdout_void::save(connection::message&  ostr) const
{
    // Nothing to do.
}


void  stdout_void::load(connection::message&  istr)
{
    // Nothing to do.
}


void  stdout_void::write(location_id const  id, natural_8_bit const*  ptr, natural_8_bit const  count)
{
    // Nothing to do.
}


}
