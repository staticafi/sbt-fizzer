#include <boost/asio/spawn.hpp>

#include <connection/server.hpp>
#include <connection/client.hpp>
#include <iomodels/iomanager.hpp>
#include <fuzzing/fuzzing_run.hpp>
#include <fuzzing/fuzzers_map.hpp>
#include <utility/timeprof.hpp>

#include <sstream>
#include <chrono>
#include <iostream>

namespace  connection {


server::server(uint16_t port, std::string path_to_client):
    acceptor(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
    client_executor(10, 
                    path_to_client.empty() ? "" : 
                        std::move(path_to_client) + " --port " + std::to_string(port) + 
                        " --max_trace_size " + std::to_string(iomodels::iomanager::instance().get_trace_max_size()), 
                    connections)
    {}


void server::start() {
    accept_connection();
    thread = std::thread([this]() {io_context.run();});
}


void server::stop() {
    io_context.stop();
    if (thread.joinable()) {
        thread.join();
    }
}


void server::accept_connection() {
    acceptor.async_accept(
        [this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
            if (!ec) {
                auto new_connection = std::make_shared<connection>(io_context, std::move(socket));
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

        throw fuzzing::fuzzer_interrupt_exception(
            "Unknown client crash during execution on input " + 
            input);
    }
    else if (ec) {
        throw ec;
    }
    switch (results_from_client.type()) {
        case message_type::results_from_client_normal:
        case message_type::results_from_client_abort_reached:
        case message_type::results_from_client_error_reached:
            break;
        case message_type::results_from_client_max_trace_reached:
            iomodels::iomanager::instance().received_message_type = 
                message_type::results_from_client_max_trace_reached;
            break;
        default:
            break;
    }

    iomodels::iomanager::instance().clear_trace();
    iomodels::iomanager::instance().load_trace(results_from_client);
    iomodels::iomanager::instance().clear_stdin();
    iomodels::iomanager::instance().load_stdin(results_from_client);
    iomodels::iomanager::instance().clear_stdout();
    iomodels::iomanager::instance().load_stdout(results_from_client);
}


void  server::fuzzing_loop(std::shared_ptr<fuzzing::fuzzer_base> const  fuzzer)
{
    using namespace std::chrono_literals;
    while (true)
    {
        if (auto excptr = client_executor.get_exception_ptr()) {
            std::rethrow_exception(excptr);
        }
        if (auto connection = connections.wait_and_pop_or_timeout(2000ms)) {
            fuzzer->_on_driver_begin();
            send_input_to_client_and_receive_result(*connection);
            fuzzer->_on_driver_end();
        }
    }
}


fuzzing::analysis_outcomes  server::run_fuzzing(std::string const&  fuzzer_name, fuzzing::termination_info const&  info)
{
    ASSUMPTION(fuzzing::get_fuzzers_map().count(fuzzer_name) != 0UL);
    client_executor.start();
    fuzzing::analysis_outcomes results = fuzzing::run(*this, fuzzing::get_fuzzers_map().at(fuzzer_name)(info));
    client_executor.stop();
    return results;
}

}
