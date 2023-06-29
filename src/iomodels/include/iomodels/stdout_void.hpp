#ifndef IOMODELS_STDOUT_VOID_HPP_INCLUDED
#   define IOMODELS_STDOUT_VOID_HPP_INCLUDED

#   include <iomodels/stdout_base.hpp>

namespace  iomodels {


struct stdout_void : public stdout_base
{
    void  clear() override;
    void  save(connection::message&  dest) const override;
    void  save(connection::shared_memory&  dest) const override;
    void  load(connection::message&  src) override;
    void  load(connection::shared_memory&  src) override;
    void  write(natural_8_bit const*  ptr, type_of_input_bits  type, connection::shared_memory&  dest) override;
};


}

#endif
