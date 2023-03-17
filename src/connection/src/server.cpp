#include <boost/asio/spawn.hpp>

#include <connection/server.hpp>
#include <connection/client.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/timeprof.hpp>
#include <utility/config.hpp>

#include <sstream>
#include <chrono>
#include <iostream>

#if COMPILER() == COMPILER_VC()
#   pragma warning(disable:4996) // warning C4996: 'sprintf': This function or variable may be unsafe.
#endif

namespace  connection {


server::server(uint16_t port, std::string path_to_client):
    acceptor(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
    client_executor_(10, 
                    path_to_client.empty() ? "" : 
                        std::move(path_to_client) +
                        " --port " + std::to_string(port) +
                        " --max_trace_length " + std::to_string(iomodels::iomanager::instance().get_config().max_trace_length) +
                        " --max_stack_size " + std::to_string(iomodels::iomanager::instance().get_config().max_stack_size) +
                        " --max_stdin_bits " + std::to_string(iomodels::iomanager::instance().get_config().max_stdin_bits) +
                        " --stdin_model " + iomodels::iomanager::instance().get_config().stdin_model_name +
                        " --stdout_model " + iomodels::iomanager::instance().get_config().stdout_model_name,
                    connections)
    {}


void server::start() {
    accept_connection();
    thread = std::thread([this]() {io_context.run();});
    client_executor_.start();
}


void server::stop() {
    client_executor_.stop();
    io_context.stop();
    if (thread.joinable()) {
        thread.join();
    }
}


void  server::send_input_to_client_and_receive_result()
{
    using namespace std::chrono_literals;
    if (auto excptr = client_executor_.get_exception_ptr()) {
        std::rethrow_exception(excptr);
    }
    if (auto connection = connections.wait_and_pop_or_timeout(2000ms)) {
        send_input_to_client_and_receive_result(*connection);
    }
}


void server::accept_connection() {
    acceptor.async_accept(
        [this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
            if (!ec) {
                auto new_connection = std::make_shared<connection>(std::move(socket));
                connections.push(std::move(new_connection));
            }
            else {
                std::cerr << "ERROR: accepting connection\n" << ec.message() << "\n";
            }
            accept_connection();
        }
    );
}


void  server::send_input_to_client_and_receive_result(std::shared_ptr<connection> connection)
{
    message input_to_client;
    iomodels::iomanager::instance().save_stdin(input_to_client);
    iomodels::iomanager::instance().save_stdout(input_to_client);

    boost::system::error_code ec;
    connection->send_message(input_to_client, ec);

    message results_from_client;
    connection->receive_message(results_from_client, ec);
    if (ec == boost::asio::error::eof) {
        vecu8  byte_values;
        bits_to_bytes(iomodels::iomanager::instance().get_stdin()->get_bits(), byte_values);
        std::string input(byte_values.size() * 2 + 1, '\0');
        for (std::size_t i = 0; i < byte_values.size(); ++i) {
            std::sprintf(input.data() + i * 2, "%02x", byte_values[i]);
        }

        throw client_crash_exception(
            "Client crash during execution on input " + 
            input);
    }
    else if (ec) {
        throw ec;
    }

    iomodels::iomanager::instance().load_termination(results_from_client);
    iomodels::iomanager::instance().clear_trace();
    iomodels::iomanager::instance().load_trace(results_from_client);
    iomodels::iomanager::instance().clear_br_instr_trace();
    iomodels::iomanager::instance().load_br_instr_trace(results_from_client);
    iomodels::iomanager::instance().clear_stdin();
    iomodels::iomanager::instance().load_stdin(results_from_client);
    iomodels::iomanager::instance().clear_stdout();
    iomodels::iomanager::instance().load_stdout(results_from_client);
}


}
