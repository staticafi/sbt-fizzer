#include <iomodels/configuration.hpp>
#include <iomodels/models_map.hpp>
#include <instrumentation/data_record_id.hpp>
#include <optional>

using namespace instrumentation;

namespace iomodels {


size_t configuration::required_shared_memory_size() const {
    size_t data_id_size = sizeof(data_record_id);
    size_t termination_record_size = data_id_size + sizeof(target_termination);
    size_t branching_record_size = data_id_size + branching_coverage_info::flattened_size();
    size_t br_instr_record_size = data_id_size + br_instr_coverage_info::flattened_size();
    size_t stdin_max_size =
        iomodels::get_stdin_models_map()
            .at(stdin_model_name)(max_stdin_bytes)
            ->max_flattened_size();

    return data_id_size + sizeof(target_termination) +
           branching_record_size * max_trace_length +
           br_instr_record_size * max_br_instr_trace_length +
           data_id_size * max_stdin_bytes + stdin_max_size;
}

template <typename Medium>
void configuration::save(Medium& dest) const {
    dest << max_trace_length;
    dest << max_br_instr_trace_length;
    dest << max_stack_size;
    dest << max_stdin_bytes;
    dest << stdin_model_name;
    dest << stdout_model_name;
}

template void configuration::save(connection::shared_memory&) const;
template void configuration::save(connection::message&) const;

template <typename Medium>
void configuration::load(Medium& src) {
    src >> max_trace_length;
    src >> max_br_instr_trace_length;
    src >> max_stack_size;
    src >> max_stdin_bytes;
    src >> stdin_model_name;
    src >> stdout_model_name;
}

template void configuration::load(connection::shared_memory&);
template void configuration::load(connection::message&);

}
