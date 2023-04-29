#include <boost/asio/spawn.hpp>

#include <connection/server.hpp>
#include <connection/client_crash_exception.hpp>
#include <connection/client_configuration.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/timeprof.hpp>
#include <utility/config.hpp>

#include <iostream>

namespace  connection {


server::server(uint16_t port):
    acceptor(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port))
    {}


void server::start() {
    accept_connections();
    io_context_thread = std::thread([this]() {io_context.run();});
}


void server::stop() {
    io_context.stop();
    if (io_context_thread.joinable()) {
        io_context_thread.join();
    }
}


void  server::send_input_to_client_and_receive_result(const client_configuration& config)
{
    using namespace std::chrono_literals;
    if (client_executor_excptr) {
        std::rethrow_exception(client_executor_excptr);
    }
    if (auto connection = connections.wait_and_pop_or_timeout(2000ms)) {
        try {
            send_input_to_client(*connection, config);
            receive_result_from_client(*connection);
        }
        catch (const boost::system::system_error& e) {
            if (e.code() == boost::asio::error::eof) {
                throw client_crash_exception("The client disconnected unexpectedly during communication");
            }
            else {
                throw e;
            }
        }
    }
    else {
        throw client_crash_exception("No client connected in time");
    }
}


void server::accept_connections() {
    acceptor.async_accept(
        [this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
            if (!ec) {
                connections.push(connection(std::move(socket)));
            }
            else {
                std::cerr << "ERROR: accepting connection\n" << ec.message() << "\n";
            }
            accept_connections();
        }
    );
}


void  server::send_input_to_client(connection& connection, const client_configuration& config) {
    message input_to_client;
    config.save(input_to_client);
    iomodels::iomanager::instance().get_config().save(input_to_client);
    iomodels::iomanager::instance().get_stdin()->save(input_to_client);
    iomodels::iomanager::instance().get_stdout()->save(input_to_client);
    connection.send_message(input_to_client);
}


void  server::receive_result_from_client(connection& connection) {
    message results_from_client;
    connection.receive_message(results_from_client);

    iomodels::iomanager::instance().clear_trace();
    iomodels::iomanager::instance().clear_br_instr_trace();
    iomodels::iomanager::instance().get_stdin()->clear();
    iomodels::iomanager::instance().get_stdout()->clear();
    iomodels::iomanager::instance().load_results(results_from_client);
}


}
