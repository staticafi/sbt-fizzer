#ifndef BENCHMARKS_BENCHMARKD_HPP_INCLUDED
#   define BENCHMARKS_BENCHMARKD_HPP_INCLUDED

#   include <instrumentation/instrumentation.hpp>
#   include <string>
#   include <unordered_map>

namespace benchmarks {


using benchmarks_map = std::unordered_map<std::string, DRIVER_TYPE_>;
benchmarks_map const&  get_benchmarks_map();


}

#endif
