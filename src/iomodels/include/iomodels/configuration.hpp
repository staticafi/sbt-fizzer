#ifndef IOMODELS_CONFIGURATION_HPP_INCLUDED
#   define IOMODELS_CONFIGURATION_HPP_INCLUDED

#   include <iomodels/stdin_base.hpp>


namespace iomodels {

struct  configuration
{
    natural_32_bit required_shared_memory_size() const;
    void invalidate_shared_memory_size_cache() const;

    template <typename Medium>
    void save_target_config(Medium& dest) const;
    template <typename Medium>
    void load_target_config(Medium& src);
    template <typename Medium>
    void save_client_config(Medium& dest) const;

    bool operator==(configuration const&  other) const;
    bool operator!=(configuration const&  other) const { return !(*this == other);}

    static std::size_t flattened_size();

    // 
    mutable std::optional<natural_32_bit> shared_memory_size_cache;

    // not used by sbt-fizzer_target
    natural_16_bit max_exec_milliseconds { 250 };

    // used by sbt-fizzer_target
    natural_32_bit  max_trace_length { 10000 };
    natural_32_bit max_br_instr_trace_length { 30000 };
    natural_8_bit  max_stack_size { 25 };
    stdin_base::byte_count_type  max_stdin_bytes { 1800 }; // Standard page: 60 * 30 chars.
    natural_16_bit  max_exec_megabytes { 1024 };
    std::string  stdin_model_name{ "stdin_replay_bytes_then_repeat_85" };
    std::string  stdout_model_name{ "stdout_void" }; 
};



}

#endif
