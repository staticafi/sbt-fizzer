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
    iomanager.set_stdout(std::make_shared<iomodels::stdout_void>());

    boost::asio::io_context io_context;
    connection::kleeient kleeient = connection::kleeient::get_instance(io_context);

    kleeient.run(
        get_program_options()->value("address"),
        get_program_options()->value("port"));
    io_context.run();
}
