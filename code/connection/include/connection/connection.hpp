#ifndef CONNECTION_CONNECTION_HPP_INCLUDED
#   define CONNECTION_CONNECTION_HPP_INCLUDED

#   include <boost/asio.hpp>

#   include <connection/message.hpp>

namespace connection {


struct connection {
    connection(boost::asio::io_context& io_context, boost::asio::ip::tcp::socket socket);

    template <typename CompletionToken>
    auto async_send_message(message& message, CompletionToken&& token) {
        typedef enum { header, body, finished } states;
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)>(
            [this, &message, state = states::header](auto& self, const boost::system::error_code& ec = {}, std::size_t n = 0) mutable {
                switch (state) {
                    case header:
                        state = states::body;
                        boost::asio::async_write(socket, boost::asio::buffer(&message.header, sizeof(message_header)), std::move(self));
                        break;
                    case body:
                        state = states::finished;
                        if (!ec) {
                            boost::asio::async_write(socket, boost::asio::buffer(message.bytes.data() + message.cursor, message.size()), std::move(self));
                        }
                        else {
                            self.complete(ec, 0);
                        }
                        break;
                    case finished:
                        self.complete(ec, n);
                        break;
                }
            }, token, socket
        );
    }

    template <typename CompletionToken>
    auto async_receive_message(message& dest, CompletionToken&& token) {
        typedef enum { header, body, finished } states;
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, std::size_t)>(
            [this, &dest, state = states::header](auto& self, const boost::system::error_code& ec = {}, std::size_t n = 0) mutable {
                switch (state) {
                    case header:
                        state = states::body;
                        boost::asio::async_read(socket, boost::asio::buffer(&dest.header, sizeof(message_header)), std::move(self));
                        break;
                    case body:
                        state = states::finished;
                        if (!ec) {
                            dest.bytes.resize(dest.size());
                            boost::asio::async_read(socket, boost::asio::buffer(dest.bytes), std::move(self));
                        }
                        else {
                            self.complete(ec, 0);
                        }
                        break;
                    case finished:
                        self.complete(ec, n);
                        break;
                }
            }, token, socket
        );  
    }

    std::size_t receive_message(message& dest, boost::system::error_code& ec);
    std::size_t receive_message(message& dest);
    std::size_t send_message(message& message, boost::system::error_code& ec);
    std::size_t send_message(message& message);

private:
    boost::asio::io_context& io_context;
    boost::asio::ip::tcp::socket socket;

};

}
#endif