#include <iostream>

#include <client/client_options.hpp>
#include <iomodels/iomanager.hpp>
#include <iomodels/stdin_replay_bits_then_repeat_85.hpp>
#include <iomodels/stdout_void.hpp>
#include <connection/medium.hpp>
#include <utility/math.hpp>
#include <instrumentation/instrumentation_types.hpp>

extern "C" {
void __sbt_fizzer_method_under_test();
}

void run(int argc, char *argv[]) {
    if (client_options::instance().parse_client_options(argc, argv)) {
        return;
    }

    iomodels::iomanager& iomanager = iomodels::iomanager::instance();

    iomanager.set_stdin(std::make_shared<iomodels::stdin_replay_bits_then_repeat_85>());
    iomanager.set_stdout(std::make_shared<iomodels::stdout_void>());
    iomanager.clear_trace();
    iomanager.clear_stdin();
    iomanager.clear_stdout();

    vecu8& bytes = client_options::instance().input_bytes;

    for (natural_8_bit byte: bytes) {
        connection::medium::instance() << byte;
    }

    iomanager.load_stdin(connection::medium::instance());
    iomanager.load_stdout(connection::medium::instance());
    
    __sbt_fizzer_method_under_test();

    for (const instrumentation::branching_coverage_info& info: iomanager.get_trace()) {
        std::cout << "location: " << info.branching_id
                  << " branch: " << info.covered_branch
                  << " distance: " << info.distance_to_uncovered_branch
                  << std::endl;
    }
}