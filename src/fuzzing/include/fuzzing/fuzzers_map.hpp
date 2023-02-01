#ifndef FUZZING_FUZZERS_MAP_HPP_INCLUDED
#   define FUZZING_FUZZERS_MAP_HPP_INCLUDED

#   include <fuzzing/fuzzer_base.hpp>
#   include <fuzzing/termination_info.hpp>
#   include <string>
#   include <functional>
#   include <unordered_map>
#   include <memory>

namespace  fuzzing {


using fuzzers_map = std::unordered_map<std::string, std::function<std::shared_ptr<fuzzer_base>(termination_info const&)> >;

fuzzers_map const&  get_fuzzers_map();

}

#endif
