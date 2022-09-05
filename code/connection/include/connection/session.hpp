#ifndef CONNECTION_SESSION_HPP_INCLUDED
#   define CONNECTION_SESSION_HPP_INCLUDED

#   include <boost/asio.hpp>

#   include <connection/medium.hpp>

namespace connection {


struct session {
    session(boost::asio::io_context& io_context, boost::asio::ip::tcp::socket socket, medium& in_buffer, medium& out_buffer);

    void send_input_to_client();
    void receive_input_from_client();

private:
    boost::asio::io_context& io_context;
    boost::asio::ip::tcp::socket socket;
    medium& in_buffer;
    medium& out_buffer;

};

}
#endif