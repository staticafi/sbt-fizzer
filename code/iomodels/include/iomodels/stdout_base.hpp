#ifndef IOMODELS_STDOUT_BASE_HPP_INCLUDED
#   define IOMODELS_STDOUT_BASE_HPP_INCLUDED

#   include <instrumentation/instrumentation_types.hpp>
#   include <connection/medium.hpp>
#   include <utility/basic_numeric_types.hpp>
#   include <memory>

namespace  iomodels {


using namespace instrumentation;


struct  stdout_base
{
    virtual ~stdout_base() = default;

    virtual void  clear() = 0;
    virtual void  save(connection::medium&  ostr) const = 0;
    virtual void  load(connection::medium&  istr) = 0;

    virtual void  write(location_id  id, natural_8_bit const*  ptr, natural_8_bit  count) = 0;
};


using  stdout_base_ptr = std::shared_ptr<stdout_base>;


}

#endif
