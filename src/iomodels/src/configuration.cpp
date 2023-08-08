#include <iomodels/configuration.hpp>
#include <iomodels/models_map.hpp>
#include <instrumentation/data_record_id.hpp>
#include <optional>

using namespace instrumentation;

namespace iomodels {


bool configuration::operator==(configuration const&  other) const
{
    return
        max_exec_milliseconds == other.max_exec_milliseconds &&     
        max_trace_length == other.max_trace_length &&
        max_stack_size == other.max_stack_size &&
        max_stdin_bytes == other.max_stdin_bytes &&
        max_exec_megabytes == other.max_exec_megabytes &&
        stdin_model_name == other.stdin_model_name &&
        stdout_model_name == other.stdout_model_name;
}

void configuration::invalidate_shared_memory_size_cache() const {
    shared_memory_size_cache.reset();
}


natural_32_bit configuration::required_shared_memory_size() const {
    if (shared_memory_size_cache.has_value()) {
        return shared_memory_size_cache.value();
    }

    std::size_t const  data_id_size = sizeof(data_record_id);
    std::size_t const  termination_record_size = data_id_size + sizeof(target_termination);
    std::size_t const  branching_record_size = data_id_size + branching_coverage_info::flattened_size();
    std::size_t const  br_instr_record_size = data_id_size + br_instr_coverage_info::flattened_size();
    std::size_t const  stdin_min_size = data_id_size + iomodels::get_stdin_models_map().at(stdin_model_name)(max_stdin_bytes)->min_flattened_size();

    natural_32_bit const  result = (natural_32_bit) (
            flattened_size() +
            termination_record_size +
            branching_record_size * max_trace_length +
            br_instr_record_size * max_br_instr_trace_length +
            stdin_min_size * max_stdin_bytes
            );

    shared_memory_size_cache = result;

    return result;
}


template<typename T>
static std::size_t  longest_key(std::unordered_map<std::string, T> const&  map)
{
    std::string str{};
    for (auto const& name_and_fn : map)
        if (str.size() < name_and_fn.first.size())
            str = name_and_fn.first;
    return str.size();
}


std::size_t configuration::flattened_size() {
    static std::size_t const  max_stdin_key_size = longest_key(iomodels::get_stdin_models_map());
    static std::size_t const  max_stdout_key_size = longest_key(iomodels::get_stdin_models_map());
    return  sizeof(max_trace_length) +
            sizeof(max_br_instr_trace_length) +
            sizeof(max_stack_size) +
            sizeof(max_stdin_bytes) +
            sizeof(max_exec_megabytes) +
            max_stdin_key_size +
            max_stdout_key_size;
}


template <typename Medium>
void configuration::save_target_config(Medium& dest) const {
    dest << max_trace_length;
    dest << max_br_instr_trace_length;
    dest << max_stack_size;
    dest << max_stdin_bytes;
    dest << max_exec_megabytes;
    dest << stdin_model_name;
    dest << stdout_model_name;
}

template void configuration::save_target_config(connection::shared_memory&) const;
template void configuration::save_target_config(connection::message&) const;

template <typename Medium>
void configuration::load_target_config(Medium& src) {
    src >> max_trace_length;
    src >> max_br_instr_trace_length;
    src >> max_stack_size;
    src >> max_stdin_bytes;
    src >> max_exec_megabytes;
    src >> stdin_model_name;
    src >> stdout_model_name;
}

template void configuration::load_target_config(connection::shared_memory&);
template void configuration::load_target_config(connection::message&);

template <typename Medium>
void configuration::save_client_config(Medium& dest) const {
    dest << required_shared_memory_size();
    dest << max_exec_milliseconds;
}

template void configuration::save_client_config(connection::shared_memory&) const;
template void configuration::save_client_config(connection::message&) const;

}
