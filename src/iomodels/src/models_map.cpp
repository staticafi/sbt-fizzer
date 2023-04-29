#include <iomodels/models_map.hpp>
#include <iomodels/stdin_replay_bytes_then_repeat_byte.hpp>
#include <iomodels/stdout_void.hpp>

namespace iomodels {

std::unordered_map<std::string, std::function<stdin_base_ptr(stdin_base::byte_count_type)>> const&  get_stdin_models_map()
{
    static std::unordered_map<std::string, std::function<stdin_base_ptr(stdin_base::byte_count_type)>> const  models {
        { "stdin_replay_bytes_then_repeat_85", [](stdin_base::byte_count_type const  max_bits){
            return std::make_unique<stdin_replay_bytes_then_repeat_byte>(max_bits, 85); } },
        { "stdin_replay_bits_then_repeat_zero", [](stdin_base::byte_count_type const  max_bits){
            return std::make_unique<stdin_replay_bytes_then_repeat_byte>(max_bits, 0); } }
    };
    return models;
}


std::unordered_map<std::string, std::function<stdout_base_ptr()>> const&  get_stdout_models_map()
{
    static std::unordered_map<std::string, std::function<stdout_base_ptr()>> const  models {
        { "stdout_void", [](){ return std::make_unique<stdout_void>(); } }
    };
    return models;
}

}