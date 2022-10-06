#ifndef IOMODELS_STDOUT_VOID_HPP_INCLUDED
#   define IOMODELS_STDOUT_VOID_HPP_INCLUDED

#   include <iomodels/stdout_base.hpp>

namespace  iomodels {


struct stdout_void : public stdout_base
{
    void  clear() override;
    void  save(connection::message&  ostr) const override;
    void  load(connection::message&  istr) override;
    void  write(location_id  id, natural_8_bit const*  ptr, natural_8_bit  count) override;
};


}

#endif
