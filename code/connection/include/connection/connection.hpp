#ifndef CONNECTION_CONNECTION_HPP_INCLUDED
#   define CONNECTION_CONNECTION_HPP_INCLUDED

#   include <boost/asio.hpp>

#   include <connection/medium.hpp>

namespace connection {


struct connection {
    connection(boost::asio::io_context& io_context, boost::asio::ip::tcp::socket socket, medium& buffer);

    template <typename CompletionToken>
    auto send_input_to_client(CompletionToken&& token) {
        return buffer.async_send_bytes(socket, std::forward<CompletionToken>(token));
    }

    template <typename CompletionToken>
    auto receive_input_from_client(CompletionToken&& token) {
        return buffer.async_receive_bytes(socket, std::forward<CompletionToken>(token));
    }

private:
    boost::asio::io_context& io_context;
    boost::asio::ip::tcp::socket socket;
    medium& buffer;

};

}
#endif