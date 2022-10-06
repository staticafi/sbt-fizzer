#ifndef IOMODELS_STDIN_BASE_HPP_INCLUDED
#   define IOMODELS_STDIN_BASE_HPP_INCLUDED

#   include <instrumentation/instrumentation_types.hpp>
#   include <connection/message.hpp>
#   include <utility/math.hpp>
#   include <memory>

namespace  iomodels {


using namespace instrumentation;


struct  stdin_base
{
    virtual ~stdin_base() = default;

    virtual void  clear() = 0;
    virtual void  save(connection::message&  ostr) const = 0;
    virtual void  load(connection::message&  istr) = 0;

    virtual void  read(location_id  id, natural_8_bit*  ptr, natural_8_bit  count) = 0;

    virtual vecb const&  get_bits() const = 0;
    virtual vecu8 const&  get_counts() const = 0;
};


using  stdin_base_ptr = std::shared_ptr<stdin_base>;


}

#endif
