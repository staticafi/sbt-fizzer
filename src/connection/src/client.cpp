#include <connection/client.hpp>
#include <connection/message.hpp>
#include <connection/connection.hpp>
#include <connection/client_configuration.hpp>
#include <iomodels/ioexceptions.hpp>

namespace  connection {


client::client(boost::asio::io_context& io_context, target_executor executor):
    io_context(io_context),
    executor(std::move(executor))
    {}


void client::run(const std::string& address, const std::string& port) {
    connect(address, port);

    try {
        receive_input();
        execute_program_and_send_results();
    }
    catch (boost::system::system_error const& e) {
        if (e.code() == boost::asio::error::eof) {
            return;
        }
        throw e;
    }
}

void client::connect(const std::string& address, const std::string& port) {
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(address, port);

    boost::asio::ip::tcp::socket socket(io_context);
    boost::asio::connect(socket, endpoints);
    connection_to_server = std::make_unique<connection>(std::move(socket));
}

void client::receive_input() {

    message input;
    connection_to_server->receive_message(input);
    client_configuration config;
    config.load(input);
    executor.shared_memory.remove();
    executor.timeout_ms = config.timeout_ms;
    executor.init_shared_memory(config.required_shared_memory_size);

    executor.shared_memory.load(input);
}


void client::execute_program_and_send_results() {
    executor.execute_target();

    message results;
    executor.shared_memory.save(results);
    executor.shared_memory.remove();
    connection_to_server->send_message(results);
}


}
