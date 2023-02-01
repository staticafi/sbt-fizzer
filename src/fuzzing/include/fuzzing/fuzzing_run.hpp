#ifndef FUZZING_FUZZING_LOOP_HPP_INCLUDED
#   define FUZZING_FUZZING_LOOP_HPP_INCLUDED

#   include <fuzzing/fuzzer_base.hpp>
#   include <fuzzing/analysis_outcomes.hpp>
#   include <connection/server.hpp>
#   include <memory>

namespace  fuzzing {


analysis_outcomes  run(connection::server& server, std::shared_ptr<fuzzer_base> const  fuzzer);


}

#endif
