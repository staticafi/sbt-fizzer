#ifndef CONNECTION_SERVER_MAIN_HPP_INCLUDED
#   define CONNECTION_SERVER_MAIN_HPP_INCLUDED

#   include <fuzzing/analysis_outcomes.hpp>
#   include <fuzzing/termination_info.hpp>
#   include <string>

namespace  connection {


fuzzing::analysis_outcomes  server_main(std::string const&  fuzzer_name, fuzzing::termination_info const&  info);


}

#endif
