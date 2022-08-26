#ifndef CONNECTION_MEDIUM_HPP_INCLUDED
#   define CONNECTION_MEDIUM_HPP_INCLUDED

#   include <utility/math.hpp>

namespace  connection {


struct  medium
{
    static medium&  instance();

    void  clear();

    medium&  operator<<(bool  v) { return operator<<((natural_8_bit)v); }
    medium&  operator>>(bool&  v) { natural_8_bit x; operator>>(x); v = x != 0; return *this; }

    template<typename T>
    medium&  operator<<(T const  v)
    {
        save_bytes((natural_8_bit const*)&v, (natural_32_bit)sizeof(v));
        return *this;
    }

    template<typename T>
    medium&  operator>>(T&  v)
    {
        load_bytes((natural_8_bit*)&v, (natural_32_bit)sizeof(v));
        return *this;
    }

private:
    medium();

    void  save_bytes(natural_8_bit const*  ptr, natural_32_bit const  count);
    void  load_bytes(natural_8_bit*  ptr, natural_32_bit const  count);

    vecu8  bytes;
    natural_16_bit  cursor;
};


}

#endif
