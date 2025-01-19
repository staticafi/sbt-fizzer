#ifndef CONNECTION_MESSAGE_HPP_INCLUDED
#   define CONNECTION_MESSAGE_HPP_INCLUDED

#   include <connection/medium.hpp>
#   include <utility/math.hpp>

#   include <cstdint>
#   include <cstring>

namespace  connection {


struct message_header {
private:
    natural_32_bit size = 0;

friend struct message;
};


struct  message : public medium 
{
    message() : medium() {}

    natural_32_bit size();

    void clear() override;
    bool empty();
    bool can_accept_bytes(size_t n) const override;
    bool can_deliver_bytes(size_t n) const override;
    void accept_bytes(const void* src, size_t n) override;
    void deliver_bytes(void* dest, size_t n) override;

    bool exhausted() const;

    template<typename T, typename std::enable_if<std::is_trivially_copyable<T>::value, int>::type = 0>
    message&  operator<<(const T& src)
    {
        accept_bytes(&src, sizeof(T));
        return *this;
    }

    message& operator<<(const std::string& src);

    template<typename T, typename std::enable_if<std::is_trivially_copyable<T>::value, int>::type = 0>
    message&  operator>>(T& dest)
    {
        deliver_bytes(&dest, sizeof(T));
        return *this;
    }

    message& operator>>(std::string& dest);


    message_header header{};
private:
    vecu8  bytes{};
    natural_32_bit  cursor = 0;
    
friend struct connection;
};

}

#endif