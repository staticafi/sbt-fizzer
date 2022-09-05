#ifndef CONNECTION_MEDIUM_HPP_INCLUDED
#   define CONNECTION_MEDIUM_HPP_INCLUDED

#   include <boost/asio.hpp>

#   include <utility/math.hpp>

#   include <iostream>

namespace  connection {


struct  medium
{
    void  clear();

    bool  empty();

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

    template <typename TCallback>
    void send_bytes(boost::asio::ip::tcp::socket& socket, TCallback callback) {
        size_t size = bytes.size();
        boost::asio::async_write(socket, boost::asio::buffer(&size, sizeof(natural_32_bit)), 
            [this, &socket, size, callback](boost::system::error_code ec, std::size_t) {
                if (ec) {
                    std::cout << "ERROR: writing data length" << std::endl;
                    return;
                }
                boost::asio::async_write(socket, boost::asio::buffer(bytes.data(), (natural_32_bit) size),
                    [this, callback](boost::system::error_code ec, std::size_t) {
                        if (ec) {
                            std::cout << "ERROR: writing data" << std::endl;
                            return;
                        }
                        callback();
                    });
            });
    }

    template <typename TCallback>
    void receive_bytes(boost::asio::ip::tcp::socket& socket, TCallback callback) {
        natural_32_bit size;
        boost::asio::async_read(socket, boost::asio::buffer(&size, sizeof(natural_32_bit)), 
            [this, &socket, size, callback](boost::system::error_code ec, std::size_t) {
                if (ec) {
                    std::cout << "ERROR: reading data length" << std::endl;
                    return;
                }
                bytes.resize(cursor + size);
                boost::asio::async_read(socket, boost::asio::buffer(bytes.data() + cursor, size),
                    [this, callback](boost::system::error_code ec, std::size_t) {
                        if (ec) {
                            std::cout << "ERROR: reading data" << std::endl;
                            return;
                        }
                        callback();
                    });
            });
    }

private:

    void  save_bytes(natural_8_bit const*  ptr, natural_32_bit const  count);
    void  load_bytes(natural_8_bit*  ptr, natural_32_bit const  count);

    vecu8  bytes;
    natural_16_bit  cursor;
};


}

#endif
