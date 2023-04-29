#ifndef IOMODELS_CONFIGURATION_HPP_INCLUDED
#   define IOMODELS_CONFIGURATION_HPP_INCLUDED

#   include <iomodels/stdin_base.hpp>


namespace iomodels {

struct  configuration
{
    size_t required_shared_memory_size() const;
    template <typename Medium>
    void save(Medium& dest) const;
    template <typename Medium>
    void load(Medium& src);

    natural_32_bit  max_trace_length { 10000 };
    natural_32_bit max_br_instr_trace_length { 30000 };
    natural_8_bit  max_stack_size { 25 };
    stdin_base::byte_count_type  max_stdin_bytes{ 1800 }; // Standard page: 60 * 30 chars.
    std::string  stdin_model_name{ "stdin_replay_bytes_then_repeat_85" };
    std::string  stdout_model_name{ "stdout_void" };  
};



}

#endif
