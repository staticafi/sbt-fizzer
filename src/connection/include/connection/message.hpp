#ifndef CONNECTION_MESSAGE_HPP_INCLUDED
#   define CONNECTION_MESSAGE_HPP_INCLUDED

#   include <utility/math.hpp>

#   include <cstdint>
#   include <cstring>

namespace  connection {


struct message_header {

    natural_32_bit type = 0;
private:
    natural_32_bit size = 0;

friend struct message;
};


struct  message
{
    natural_32_bit size();

    void clear();
    bool empty();
    void load(const void* src, size_t n);
    void save(void* dest, size_t n);

    bool exhausted() const;

    template<typename T, typename std::enable_if<std::is_trivially_copyable<T>::value, int>::type = 0>
    message&  operator<<(const T& src)
    {
        load(&src, sizeof(T));
        return *this;
    }

    message& operator<<(const std::string& src);

    template<typename T, typename std::enable_if<std::is_trivially_copyable<T>::value, int>::type = 0>
    message&  operator>>(T& dest)
    {
        save(&dest, sizeof(T));
        return *this;
    }

    message& operator>>(std::string& dest);


    message_header header;
private:
    vecu8  bytes;
    natural_32_bit  cursor = 0;
    
friend struct connection;
};

}

#endif