#include <connection/kleeient_connector.hpp>
#include <connection/connection.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <utility/assumptions.hpp>
#include <iostream>

namespace  connection {

kleeient_connector::kleeient_connector(uint16_t port):
    acceptor(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)){}

bool kleeient_connector::get_model(const std::vector<bool> trace, std::vector<uint8_t>& model) {
    ASSUMPTION(kleeient_connection != nullptr);

    send_trace(trace);
    return receive_response(model);
}

void kleeient_connector::send_trace(const std::vector<bool>& trace)
{
    message msg;
    msg << (size_t) trace.size();
    for (bool dir : trace) {
        msg << dir;
    }

    boost::system::error_code ec;
    kleeient_connection->send_message(msg, ec);
    if (ec) {
        throw ec;
    }
}

bool kleeient_connector::receive_response(std::vector<uint8_t>& model)
{
    boost::system::error_code ec;
    message result;
    kleeient_connection->receive_message(result, ec);
    if (ec) {
        throw ec;
    }

    size_t size;
    result >> size;
    uint8_t byte;
    for (size_t i = 0; i < size; i++) {
        result >> byte;
        model.push_back(byte);
    }
    // TODO: send also feasibility
    return true;
}

void kleeient_connector::wait_for_connection()
{
    boost::asio::ip::tcp::socket socket(io_context);
    boost::system::error_code ec;
    acceptor.accept(socket, ec);
    if (ec) {
        throw ec;
    }
    kleeient_connection = std::make_shared<connection>(std::move(socket));
}

}
