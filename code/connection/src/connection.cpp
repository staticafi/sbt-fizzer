#include <connection/connection.hpp>
#include <iomodels/iomanager.hpp>


namespace connection {

    connection::connection(boost::asio::io_context& io_context, boost::asio::ip::tcp::socket socket, medium& buffer):
        io_context(io_context),
        socket(std::move(socket)),
        buffer(buffer)
    {}

    
}

