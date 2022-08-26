#include <connection/client_main.hpp>
#include <iomodels/iomanager.hpp>
#include <iomodels/stdin_replay_bits_then_repeat_85.hpp>
#include <iomodels/stdout_void.hpp>
#include <utility/assumptions.hpp>

#include <instrumentation/instrumentation.hpp>
#include <benchmarks/benchmarks.hpp>

namespace  connection {


DRIVER_TYPE_   benchmark_driver;


void  client_main(std::string const&  benchmark_name)
{
    iomodels::iomanager::instance().set_stdin(std::make_shared<iomodels::stdin_replay_bits_then_repeat_85>());
    iomodels::iomanager::instance().set_stdout(std::make_shared<iomodels::stdout_void>());

    ASSUMPTION(benchmarks::get_benchmarks_map().count(benchmark_name) != 0UL);
    benchmark_driver = benchmarks::get_benchmarks_map().at(benchmark_name);
}


}
