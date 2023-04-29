#ifndef IOMODELS_MODELS_MAP_HPP_INCLUDED
#   define IOMODELS_MODELS_MAP_HPP_INCLUDED

#   include <iomodels/stdin_base.hpp>
#   include <iomodels/stdout_base.hpp>
#   include <unordered_map>
#   include <string>
#   include <functional>

namespace iomodels {

std::unordered_map<std::string, std::function<stdin_base_ptr(stdin_base::byte_count_type)>> const&  get_stdin_models_map();

std::unordered_map<std::string, std::function<stdout_base_ptr()>> const&  get_stdout_models_map();
}



#endif