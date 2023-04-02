#include <boost/algorithm/hex.hpp>

#include <connection/client.hpp>
#include <connection/message.hpp>
#include <connection/connection.hpp>
#include <instrumentation/exceptions.hpp>
#include <iomodels/iomanager.hpp>
#include <iomodels/ioexceptions.hpp>

#include <iostream>

extern "C" {
void __sbt_fizzer_method_under_test();
}

namespace  connection {

client::client(boost::asio::io_context& io_context):
    io_context(io_context)
    {}


void client::execute_program() {
    iomodels::iomanager::instance().set_termination(iomodels::iomanager::NORMAL);
    iomodels::iomanager::instance().clear_trace();
    iomodels::iomanager::instance().clear_br_instr_trace();
    try {
        __sbt_fizzer_method_under_test();
    }
    catch (const instrumentation::terminate_exception&) {
        // Nothing to do.
    }
    catch (const iomodels::execution_crashed& e) {
        std::cout << "INFO: Discovered crash in the benchmark: " << e.what() << std::endl;
        iomodels::iomanager::instance().set_termination(iomodels::iomanager::CRASH);
    }
    catch (const iomodels::boundary_condition_violation& e) {
        std::cout << "WARNING: boundary condition violation: " << e.what() << std::endl;
        iomodels::iomanager::instance().set_termination(iomodels::iomanager::BOUNDARY_CONDITION_VIOLATION);
    }
    catch (const instrumentation::error_reached_exception&) { // Why do we need this?
        std::cout << "Reached error" << std::endl;
        iomodels::iomanager::instance().set_termination(iomodels::iomanager::CRASH);
    }
}

void client::run_input_mode(vecu8 input_bytes) {
    message input;
    input << (natural_16_bit) (input_bytes.size() * 8U);
    input << (natural_16_bit) input_bytes.size();
    for (natural_8_bit byte: input_bytes) {
        input << byte;
    }
    input << (natural_16_bit) 0;

    iomodels::iomanager::instance().clear_stdin();
    iomodels::iomanager::instance().load_stdin(input);
    iomodels::iomanager::instance().clear_stdout();
    iomodels::iomanager::instance().load_stdout(input);
    
    execute_program();

    for (const instrumentation::branching_coverage_info& info: iomodels::iomanager::instance().get_trace()) {
        std::cout << "location: bb" << info.id
                  << " branch: " << std::boolalpha << info.direction
                  << " value: " << info.value
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
    
    iomodels::iomanager::instance().clear_stdin();
    iomodels::iomanager::instance().load_stdin(input);
    iomodels::iomanager::instance().clear_stdout();
    iomodels::iomanager::instance().load_stdout(input);
    return true;
}


bool client::execute_program_and_send_results()
{
    execute_program();

    std::cout << "Program finished, sending results..." << std::endl;

    message results;
    iomodels::iomanager::instance().save_termination(results);
    iomodels::iomanager::instance().save_trace(results);
    iomodels::iomanager::instance().save_br_instr_trace(results);
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
