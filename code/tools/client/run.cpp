#include <boost/algorithm/hex.hpp>
#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include <iomodels/iomanager.hpp>
#include <iomodels/stdin_replay_bits_then_repeat_85.hpp>
#include <iomodels/stdout_void.hpp>
#include <connection/medium.hpp>
#include <utility/math.hpp>
#include <instrumentation/instrumentation_types.hpp>
#include <utility/endian.hpp>
#include <client/program_options.hpp>

#include <iostream>
#include <stdlib.h>

namespace io = boost::asio;
namespace ip = io::ip;
using tcp = io::ip::tcp;
using error_code = boost::system::error_code;

extern "C" {
void __sbt_fizzer_method_under_test();
}

void run_input_mode(const std::string& input) {
    vecu8 input_bytes;
    try {
        boost::algorithm::unhex(input, std::back_inserter(input_bytes));
    } catch (boost::algorithm::hex_decode_error &e) {
        std::cout << "In argument input expected hexadecimal value" << std::endl;
        return;
    }

    iomodels::iomanager& iomanager = iomodels::iomanager::instance();

    iomanager.set_stdin(std::make_shared<iomodels::stdin_replay_bits_then_repeat_85>());
    iomanager.set_stdout(std::make_shared<iomodels::stdout_void>());
    iomanager.clear_trace();
    iomanager.clear_stdin();
    iomanager.clear_stdout();

    connection::medium::instance() << (natural_16_bit) input_bytes.size();
    for (natural_8_bit byte: input_bytes) {
        connection::medium::instance() << byte;
    }
    connection::medium::instance() << (natural_16_bit) 0;

    iomanager.load_stdin(connection::medium::instance());
    iomanager.load_stdout(connection::medium::instance());
    
    __sbt_fizzer_method_under_test();

    for (const instrumentation::branching_coverage_info& info: iomanager.get_trace()) {
        std::cout << "location: bb" << info.branching_id
                  << " branch: " << std::boolalpha << info.covered_branch
                  << " distance to uncovered branch: " << info.distance_to_uncovered_branch
                  << "\n";
    }
}

void run_connection_mode(const ip::address& address, unsigned short port) {
    io::io_context io_context;
    tcp::socket socket(io_context);
    
    error_code error;
    tcp::endpoint endpoint(address, port);

    socket.connect(endpoint, error);
    if (error) {
        std::cout << "ERROR: unable to connect." << std::endl;
        return;
    }
    
}

void run() {
    if (get_program_options()->has("input")) {
        run_input_mode(get_program_options()->value("input"));
        return;
    }
    if (!get_program_options()->has("address") || !get_program_options()->has("port")) {
        std::cout << "ERROR: no options specified. Use --help." << std::endl;
        return;
    }
    error_code error;
    ip::address address = ip::make_address(get_program_options()->value("address"), error);
    if (error) {
        std::cout << "ERROR: invalid address." << std::endl;
        return;
    }
    unsigned short port = (unsigned short) atoi(get_program_options()->value("port").c_str());
    
    run_connection_mode(address, port);
    
}