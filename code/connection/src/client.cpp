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
    socket(io_context)
    {}

void client::execute_program_input_mode(const std::string& input) {
    vecu8 input_bytes;
    try {
        boost::algorithm::unhex(input, std::back_inserter(input_bytes));
    } catch (boost::algorithm::hex_decode_error &e) {
        std::cout << "In argument input expected hexadecimal value" << std::endl;
        return;
    }

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
        return;
    }

    boost::asio::async_connect(socket, endpoints, 
        [this](boost::system::error_code ec, boost::asio::ip::tcp::endpoint endpoint) {
            if (ec) {
                std::cout << "ERROR: could not connect to server" << std::endl;
                return;
            }
            receive_input();
        });
}

void client::receive_input() {
    buffer.receive_bytes(socket, execute_program_and_send_results);
}


void  client::execute_program_and_send_results()
{
    iomodels::iomanager::instance().load_stdin(buffer);
    iomodels::iomanager::instance().load_stdout(buffer);

    __sbt_fizzer_method_under_test();

    buffer.clear();
    iomodels::iomanager::instance().save_trace(buffer);
    iomodels::iomanager::instance().save_stdin(buffer);
    iomodels::iomanager::instance().save_stdout(buffer);
    buffer.send_bytes(socket, [](){});
}


}
