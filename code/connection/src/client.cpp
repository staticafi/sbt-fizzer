#include <boost/algorithm/hex.hpp>

#include <connection/client.hpp>
#include <connection/medium.hpp>
#include <iomodels/iomanager.hpp>

#include <iostream>

extern "C" {
void __sbt_fizzer_method_under_test();
}

namespace  connection {

client::client(boost::asio::io_context& io_context):
    io_context(io_context),
    socket(io_context),
    buffer()
    {}

void client::execute_program_input_mode(vecu8 input_bytes) {
    buffer << (natural_16_bit) input_bytes.size();
    for (natural_8_bit byte: input_bytes) {
        buffer << byte;
    }
    buffer << (natural_16_bit) 0;

    iomodels::iomanager::instance().load_stdin(buffer);
    iomodels::iomanager::instance().load_stdout(buffer);
    
    __sbt_fizzer_method_under_test();

    for (const instrumentation::branching_coverage_info& info: iomodels::iomanager::instance().get_trace()) {
        std::cout << "location: bb" << info.branching_id
                  << " branch: " << std::boolalpha << info.covered_branch
                  << " distance to uncovered branch: " << info.distance_to_uncovered_branch
                  << "\n";
    }
}

void client::connect(const std::string& address, const std::string& port) {
    boost::system::error_code ec;
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(address, port, ec);
    if (ec) {
        std::cout << "ERROR: could not resolve address and port" << std::endl;
        std::cout << ec.what() << std::endl;
        return;
    }

    boost::asio::async_connect(socket, endpoints, 
        [this](boost::system::error_code ec, boost::asio::ip::tcp::endpoint endpoint) {
            if (ec) {
                std::cout << "ERROR: could not connect to server" << std::endl;
                std::cout << ec.what() << std::endl;
                return;
            }
            std::cout << "Connected to server" << std::endl;
            receive_input();
        });
}

void client::receive_input() {
    std::cout << "Receiving input from server..." << std::endl;
    buffer.async_receive_bytes(socket, 
        [this](boost::system::error_code ec, std::size_t bytes_transferred) {
            if (!ec) {
                std::cout << "Received " << bytes_transferred << " bytes from server" << std::endl;
                execute_program_and_send_results();
                return;
            }
            // server was shutdown
            else if (ec == boost::asio::error::eof) {
                return;
            }
            std::cout << "ERROR: receiving input from server\n";
            std::cout << ec.what() << std::endl;
        }
    );
}


void  client::execute_program_and_send_results()
{
    iomodels::iomanager::instance().load_stdin(buffer);
    iomodels::iomanager::instance().load_stdout(buffer);

    __sbt_fizzer_method_under_test();
    std::cout << "Benchmark finished, sending results..." << std::endl;

    buffer.clear();
    iomodels::iomanager::instance().save_trace(buffer);
    iomodels::iomanager::instance().save_stdin(buffer);
    iomodels::iomanager::instance().save_stdout(buffer);
    buffer.async_send_bytes(socket, 
        [this](boost::system::error_code ec, std::size_t bytes_transferred) {
            if (!ec) {
                std::cout << "Sent " << bytes_transferred << " bytes to server" << std::endl;
                return;
            }
            std::cout << "ERROR: sending result to server\n";
            std::cout << ec.what() << std::endl;
        }
    );
}


}
