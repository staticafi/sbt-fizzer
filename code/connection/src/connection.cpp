#include <connection/connection.hpp>
#include <iomodels/iomanager.hpp>


namespace connection {

connection::connection(boost::asio::io_context& io_context, boost::asio::ip::tcp::socket socket, medium& buffer):
    io_context(io_context),
    socket(std::move(socket)),
    buffer(buffer)
{}

std::size_t connection::send_input_to_client(boost::system::error_code& ec) {
    return buffer.send_bytes(socket, ec);
}

std::size_t connection::receive_result_from_client(boost::system::error_code& ec) {
    return buffer.receive_bytes(socket, ec);
}
}

