#include <boost/algorithm/hex.hpp>

#include <connection/client.hpp>
#include <connection/message.hpp>
#include <connection/connection.hpp>
#include <iomodels/iomanager.hpp>

#include <iostream>

extern "C" {
void __sbt_fizzer_method_under_test();
}

namespace  connection {

client::client(boost::asio::io_context& io_context):
    io_context(io_context)
    {}


message_type client::execute_program() {
    try {
        __sbt_fizzer_method_under_test();
        return message_type::results_from_client_normal;
    }
    catch (const iomodels::trace_max_size_reached_exception&) {
        std::cout << "WARNING: terminated early because maximum allowed trace size was reached" << std::endl;
        return message_type::results_from_client_max_trace_reached;
    }
    catch (const instrumentation::terminate_exception&) {
        return message_type::results_from_client_normal;
    }
    catch (const instrumentation::error_reached_exception&) {
        std::cout << "Reached error" << std::endl;
        return message_type::results_from_client_error_reached;
    }
}

void client::run_input_mode(vecu8 input_bytes) {
    message input;
    input << (natural_16_bit) input_bytes.size();
    for (natural_8_bit byte: input_bytes) {
        input << byte;
    }
    input << (natural_16_bit) 0;

    iomodels::iomanager::instance().load_stdin(input);
    iomodels::iomanager::instance().load_stdout(input);
    
    execute_program();

    for (const instrumentation::branching_coverage_info& info: iomodels::iomanager::instance().get_trace()) {
        std::cout << "location: bb" << info.branching_id
                  << " branch: " << std::boolalpha << info.covered_branch
                  << " distance to uncovered branch: " << info.distance_to_uncovered_branch
                  << "\n";
    }
}

void client::run(const std::string& address, const std::string& port) {
    if (!connect(address, port)) {
        return;
    }

    if (!receive_input()) {
        return;
    }

    execute_program_and_send_results();
}

bool client::connect(const std::string& address, const std::string& port) {
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::system::error_code ec;
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(address, port, ec);
    if (ec) {
        std::cerr << "ERROR: could not resolve address and port\n" << ec.message() << "\n";
        return false;
    }

    boost::asio::ip::tcp::socket socket(io_context);
    boost::asio::connect(socket, endpoints, ec);
    if (ec) {
        std::cerr << "ERROR: could not connect to server\n" << ec.message() << "\n";
        return false;
    }
    connection_to_server = std::make_unique<connection>(std::move(socket));

    std::cout << "Connected to server" << std::endl;
    return true;
}

bool client::receive_input() {
    std::cout << "Receiving input from server..." << std::endl;

    boost::system::error_code ec;
    message input;
    connection_to_server->receive_message(input, ec);
    if (ec == boost::asio::error::eof) {
        return false;
    }
    else if (ec) {
        std::cerr << "ERROR: receiving input from server\n" << ec.message() << "\n";
        return false;
    }
    
    iomodels::iomanager::instance().load_stdin(input);
    iomodels::iomanager::instance().load_stdout(input);
    return true;
}


bool client::execute_program_and_send_results()
{
    std::cout << "Program finished, sending results..." << std::endl;
    
    message results;
    results.header.type = execute_program();
    iomodels::iomanager::instance().save_trace(results);
    iomodels::iomanager::instance().save_stdin(results);
    iomodels::iomanager::instance().save_stdout(results);

    boost::system::error_code ec;
    connection_to_server->send_message(results, ec);
    if (ec) {
        std::cerr << "ERROR: sending result to server\n" << ec.message() << "\n";
        return false;
    }

    std::cout << "Results sent to server" << std::endl;
    return true;
}


}
