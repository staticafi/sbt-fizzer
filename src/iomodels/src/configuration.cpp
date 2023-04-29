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

    size_t data_id_size = sizeof(data_record_id);
    size_t termination_record_size = data_id_size + sizeof(target_termination);
    size_t branching_record_size = data_id_size + branching_coverage_info::flattened_size();
    size_t br_instr_record_size = data_id_size + br_instr_coverage_info::flattened_size();
    size_t stdin_max_size =
        iomodels::get_stdin_models_map()
            .at(stdin_model_name)(max_stdin_bytes)
            ->max_flattened_size();

    natural_32_bit result = (natural_32_bit) (
            data_id_size + sizeof(target_termination) +
            branching_record_size * max_trace_length +
            br_instr_record_size * max_br_instr_trace_length +
            data_id_size * max_stdin_bytes + stdin_max_size
        );

    shared_memory_size_cache = result;

    return result;
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
