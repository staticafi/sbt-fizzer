#ifndef CONNECTION_MEDIUM_HPP_INCLUDED
#   define CONNECTION_MEDIUM_HPP_INCLUDED

#   include <boost/asio.hpp>
#   include <boost/asio/use_future.hpp>

#   include <utility/math.hpp>

#   include <iostream>

namespace  connection {


struct  medium
{
    medium();

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

    

    template <typename CompletionToken>
    auto async_send_bytes(boost::asio::ip::tcp::socket& socket, CompletionToken&& token) {
        typedef enum { header, body, finished } states;
        tmp_body_size = bytes.size();
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)>(
            [this, &socket, state = states::header](auto& self, const boost::system::error_code& ec = {}, std::size_t n = 0) mutable {
                switch (state) {
                    case header:
                        state = states::body;
                        boost::asio::async_write(socket, boost::asio::buffer(&tmp_body_size, sizeof(natural_32_bit)), std::move(self));
                        break;
                    case body:
                        state = states::finished;
                        std::cout << "wrote " << n << " bytes, " << "size of body: " << tmp_body_size << "\n";
                        std::cout << ec.what() << std::endl;
                        if (!ec) {
                            boost::asio::async_write(socket, boost::asio::buffer(bytes), std::move(self));
                        }
                        else {
                            self.complete(ec, 0);
                        }
                        break;
                    case finished:
                        std::cout << "wrote " << n << " bytes\n";
                        std::cout << ec.what() << std::endl; 
                        self.complete(ec, n);
                        break;
                }
            }, token, socket
        );
    }

    template <typename CompletionToken>
    auto async_receive_bytes(boost::asio::ip::tcp::socket& socket, CompletionToken&& token) {
        typedef enum { header, body, finished } states;
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)>(
            [this, &socket, state = states::header](auto& self, const boost::system::error_code& ec = {}, std::size_t n = 0) mutable {
                switch (state) {
                    case header:
                        state = states::body;
                        boost::asio::async_read(socket, boost::asio::buffer(&tmp_body_size, sizeof(natural_32_bit)), std::move(self));
                        break;
                    case body:
                        state = states::finished;
                        std::cout << "read " << n << " bytes, " << "size of body: " << tmp_body_size << "\n";
                        std::cout << ec.what() << std::endl; 
                        if (!ec) {
                            bytes.resize(tmp_body_size);
                            boost::asio::async_read(socket, boost::asio::buffer(bytes), std::move(self));
                        }
                        else {
                            self.complete(ec, 0);
                        }
                        break;
                    case finished:
                        std::cout << "read " << n << " bytes\n";
                        std::cout << ec.what() << std::endl; 
                        self.complete(ec, n);
                        break;
                }
            }, token, socket
        );  
    }

    bool empty();

private:

    void  save_bytes(natural_8_bit const*  ptr, natural_32_bit const  count);
    void  load_bytes(natural_8_bit*  ptr, natural_32_bit const  count);

    vecu8  bytes;
    natural_16_bit  cursor;

    natural_32_bit tmp_body_size;
};


}

#endif
