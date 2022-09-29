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
#include <connection/client.hpp>

#include <iostream>
#include <stdlib.h>

void run() {
    iomodels::iomanager& iomanager = iomodels::iomanager::instance();
    iomanager.set_stdin(std::make_shared<iomodels::stdin_replay_bits_then_repeat_85>());
    iomanager.set_stdout(std::make_shared<iomodels::stdout_void>());
    iomanager.set_trace_max_size(std::stoul(get_program_options()->value("max_trace_size")));

    boost::asio::io_context io_context;
    connection::client client(io_context);

    if (get_program_options()->has("input")) {
        vecu8 input_bytes;
        try {
            boost::algorithm::unhex(get_program_options()->value("input"), std::back_inserter(input_bytes));
        } 
        catch (boost::algorithm::hex_decode_error &e) {
            std::cerr << "ERROR: in argument input expected hexadecimal value\n";
            return;
        }
        client.execute_program_input_mode(std::move(input_bytes));
        return;
    }
    
    client.connect(get_program_options()->value("address"), get_program_options()->value("port"));
    io_context.run();
}