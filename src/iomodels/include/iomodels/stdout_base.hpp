#ifndef IOMODELS_STDOUT_BASE_HPP_INCLUDED
#   define IOMODELS_STDOUT_BASE_HPP_INCLUDED

#   include <instrumentation/instrumentation_types.hpp>
#   include <connection/shared_memory.hpp>
#   include <connection/message.hpp>
#   include <utility/basic_numeric_types.hpp>
#   include <memory>

namespace  iomodels {

struct  stdout_base
{
    using  type_of_input_bits = instrumentation::type_of_input_bits;

    virtual ~stdout_base() = default;

    virtual void  clear() = 0;
    virtual void  save(connection::message&  dest) const = 0;
    virtual void  save(connection::shared_memory&  dest) const = 0;
    virtual void  load(connection::message&  src) = 0;
    virtual void  load(connection::shared_memory&  src) = 0;

    virtual void  write(natural_8_bit const*  ptr, type_of_input_bits  type, connection::shared_memory&  dest) = 0;
};


using  stdout_base_ptr = std::unique_ptr<stdout_base>;


}

#endif
