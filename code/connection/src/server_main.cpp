#include <connection/server_main.hpp>
#include <fuzzing/fuzzing_loop.hpp>
#include <fuzzing/fuzzers_map.hpp>
#include <utility/assumptions.hpp>

namespace  connection {


fuzzing::analysis_outcomes  server_main(std::string const&  fuzzer_name, fuzzing::termination_info const&  info)
{
    ASSUMPTION(fuzzing::get_fuzzers_map().count(fuzzer_name) != 0UL);
    return fuzzing::run(fuzzing::get_fuzzers_map().at(fuzzer_name)(info));
}


}
