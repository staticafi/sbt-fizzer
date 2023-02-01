#ifndef CONNECTION_MESSAGE_HPP_INCLUDED
#   define CONNECTION_MESSAGE_HPP_INCLUDED

#   include <connection/message_type.hpp>
#   include <utility/math.hpp>

#   include <cstring>

namespace  connection {


struct message_header {
    message_header();
    message_header(message_type type);

    message_type type = message_type::not_set;
private:
    natural_32_bit size = 0;

friend struct message;
};


struct  message
{
    message();
    message(message_type type);

    message_type type();
    natural_32_bit size();

    void  clear();
    bool empty();

    template<typename T, typename std::enable_if<std::is_trivially_copyable<T>::value, int>::type = 0>
    message&  operator<<(const T& v)
    {
        std::size_t data_size = sizeof(T);
        std::size_t old_size = bytes.size();
        bytes.resize(old_size + data_size);
        memcpy(bytes.data() + old_size, &v, data_size);
        header.size += (natural_32_bit)data_size;
        return *this;
    }

    template<typename T, typename std::enable_if<std::is_trivially_copyable<T>::value, int>::type = 0>
    message&  operator>>(T& v)
    {
        std::size_t data_size = sizeof(T);
        ASSUMPTION(cursor + data_size <= (natural_32_bit) bytes.size());
        memcpy(&v, bytes.data() + cursor, data_size);
        cursor += (natural_32_bit)data_size;
        header.size -= (natural_32_bit)data_size;
        return *this;
    }


    message_header header{};
private:
    vecu8  bytes;
    natural_32_bit  cursor = 0;
    
friend struct connection;
};

}

#endif
