#include <boost/algorithm/hex.hpp>
#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include <iomodels/iomanager.hpp>
#include <iomodels/stdin_replay_bits_then_repeat_85.hpp>
#include <iomodels/stdout_void.hpp>
#include <connection/message.hpp>
#include <utility/math.hpp>
#include <instrumentation/instrumentation_types.hpp>
#include <utility/endian.hpp>
#include <kleeient/program_options.hpp>
#include <connection/kleeient.hpp>

#include <iostream>
#include <stdlib.h>

void run() {
    iomodels::iomanager& iomanager = iomodels::iomanager::instance();
    iomanager.set_stdin(std::make_shared<iomodels::stdin_replay_bits_then_repeat_85>(
        (natural_16_bit)std::stoul(get_program_options()->value("max_stdin_bits"))
    ));
    iomanager.set_stdout(std::make_shared<iomodels::stdout_void>());
    iomanager.set_trace_max_size(std::stoul(get_program_options()->value("max_trace_size")));

    boost::asio::io_context io_context;
    connection::kleeient kleeient = connection::kleeient::get_instance(io_context);

    if (get_program_options()->has("input")) {
        vecu8 input_bytes;
        try {
            boost::algorithm::unhex(get_program_options()->value("input"), std::back_inserter(input_bytes));
        }
        catch (boost::algorithm::hex_decode_error &) {
            std::cerr << "ERROR: in argument input expected hexadecimal value\n";
            return;
        }
        if (8ULL * input_bytes.size() > iomanager.get_stdin()->get_max_bits()) {
            std::cerr << "ERROR: the count of bits in the passed input (" << 8ULL * input_bytes.size()
                      << ") is above the limit (" << iomanager.get_stdin()->get_max_bits() << ").\n";
            return;
        }
        return;
    }


    kleeient.run(
        get_program_options()->value("address"),
        get_program_options()->value("port"));
    io_context.run();
}
