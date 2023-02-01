#include <connection/connection.hpp>
#include <iomodels/iomanager.hpp>


namespace connection {


connection::connection(boost::asio::ip::tcp::socket socket):
    socket(std::move(socket))
{}

std::size_t connection::send_message(message& message, boost::system::error_code& ec) {
    boost::asio::write(socket, boost::asio::buffer(&message.header, sizeof(message_header)), ec);
    if (ec) {
        return 0;
    }
    return boost::asio::write(socket, boost::asio::buffer(message.bytes.data() + message.cursor, message.size()), ec);
}


std::size_t connection::send_message(message& message) {
    boost::asio::write(socket, boost::asio::buffer(&message.header, sizeof(message_header)));
    return boost::asio::write(socket, boost::asio::buffer(message.bytes.data() + message.cursor, message.size()));
}


std::size_t connection::receive_message(message& dest, boost::system::error_code& ec) {
    boost::asio::read(socket, boost::asio::buffer(&dest.header, sizeof(message_header)), ec);
    if (ec) {
        return 0;
    }
    dest.bytes.resize(dest.size());
    return boost::asio::read(socket, boost::asio::buffer(dest.bytes), ec);
}


std::size_t connection::receive_message(message& dest) {
    boost::asio::read(socket, boost::asio::buffer(&dest.header, sizeof(message_header)));
    dest.bytes.resize(dest.size());
    return boost::asio::read(socket, boost::asio::buffer(dest.bytes));
}

}

