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
    using  bit_count_type = natural_16_bit;

    explicit stdin_base(bit_count_type const  max_bits_) : m_max_bits{ max_bits_ } {}
    virtual ~stdin_base() = default;

    virtual void  clear() = 0;
    virtual void  save(connection::message&  ostr) const = 0;
    virtual void  load(connection::message&  istr) = 0;
    virtual void  read(location_id  id, natural_8_bit*  ptr, natural_8_bit  count) = 0;

    virtual vecb const&  get_bits() const = 0;
    virtual vecu8 const&  get_counts() const = 0;
    virtual bit_count_type  num_bits_read() const = 0;

    virtual void  set_bits(vecb const&  bits) = 0;

    bit_count_type  max_bits() const { return m_max_bits; }

private:
    bit_count_type  m_max_bits;
};


using  stdin_base_ptr = std::shared_ptr<stdin_base>;


}

#endif
