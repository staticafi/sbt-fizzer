#include <boost/asio.hpp>

#include <client/program_options.hpp>
#include <connection/client.hpp>
#include <connection/target_executor.hpp>

#include <iostream>

void run() {
    if (!get_program_options()->has("path_to_target")) {
        std::cerr << "ERROR: no path to target specified.\n";
        return;
    }

    boost::asio::io_context io_context;
    connection::target_executor executor(get_program_options()->value("path_to_target"));
    connection::client client(io_context, std::move(executor));

    client.run(get_program_options()->value("address"), get_program_options()->value("port"));
    io_context.run();
}