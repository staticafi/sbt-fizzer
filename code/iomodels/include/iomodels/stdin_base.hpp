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
    explicit stdin_base(natural_16_bit const  max_bits_) : max_bits{ max_bits_ }, bits_read{ 0ULL } {}
    virtual ~stdin_base() = default;

    virtual void  clear() = 0; // Call from child's 'clear' method!
    virtual void  save(connection::message&  ostr) const = 0; // Call from child's 'save' method!
    virtual void  load(connection::message&  istr) = 0; // Call from child's 'load' method!
    virtual void  read(location_id  id, natural_8_bit*  ptr, natural_8_bit  count) = 0; // Call from child's 'read' method!

    virtual vecb const&  get_bits() const = 0;
    virtual vecu8 const&  get_counts() const = 0;

    natural_16_bit  get_max_bits() const { return max_bits; }
    std::size_t  get_bits_requested() const { return bits_read; }

private:
    natural_16_bit  max_bits;
    std::size_t  bits_read;
};


inline void  stdin_base::clear() { bits_read = 0; }
inline void  stdin_base::save(connection::message&  ostr) const{ ostr << get_bits_requested(); }
inline void  stdin_base::load(connection::message&  istr) { istr >> bits_read; }
inline void  stdin_base::read(location_id, natural_8_bit*, natural_8_bit const  count) { bits_read += 8U * count; }


using  stdin_base_ptr = std::shared_ptr<stdin_base>;


}

#endif
