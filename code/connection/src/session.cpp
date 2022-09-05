#include <connection/session.hpp>
#include <iomodels/iomanager.hpp>


namespace connection {

    session::session(boost::asio::io_context& io_context, boost::asio::ip::tcp::socket socket, medium& in_buffer, medium& out_buffer):
        io_context(io_context),
        socket(std::move(socket)),
        in_buffer(in_buffer),
        out_buffer(out_buffer)
    {}

    void session::send_input_to_client() {
        iomodels::iomanager::instance().save_stdin(out_buffer);
        iomodels::iomanager::instance().save_stdout(out_buffer);
        out_buffer.send_bytes(socket, std::bind(&session::receive_input_from_client, this));
    }

    void session::receive_input_from_client() {
        in_buffer.receive_bytes(socket, [](){});
    }
}

