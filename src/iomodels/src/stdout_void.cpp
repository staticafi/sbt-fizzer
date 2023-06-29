#include <iomodels/stdout_void.hpp>

namespace  iomodels {


void  stdout_void::clear()
{
    // Nothing to do.
}


void  stdout_void::save(connection::message&  dest) const
{
    // Nothing to do.
}


void  stdout_void::save(connection::shared_memory&  dest) const
{
    // Nothing to do.
}


void  stdout_void::load(connection::message&  src)
{
    // Nothing to do.
}


void  stdout_void::load(connection::shared_memory&  src)
{
    // Nothing to do.
}


void  stdout_void::write(natural_8_bit const*  ptr, type_of_input_bits const  type, connection::shared_memory&  dest)
{
    // Nothing to do.
}


}
