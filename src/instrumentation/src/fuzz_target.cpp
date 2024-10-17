#include <instrumentation/fuzz_target.hpp>
#include <utility/hash_combine.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <cmath>
#include <instrumentation/data_record_id.hpp>
#include <instrumentation/target_termination.hpp>
#include <iomodels/models_map.hpp>

using namespace iomodels;

namespace instrumentation {

fuzz_target::fuzz_target():
      trace_length{0}
    , br_instr_trace_length{0}
    , context_hashes{ 0U }
    , locations{}
    , config{}
    , stdin_model{ nullptr }
    , stdout_model{ nullptr }
    , shared_memory{}
{
    INVARIANT(context_hashes.size() == locations.size() + 1);
}


void fuzz_target::process_condition(
        location_id::id_type const id_type,
        bool const direction,
        branching_function_value_type value,
        bool const xor_like_branching_function,
        natural_8_bit const predicate
        )
{
    if (stdin_model->num_bytes_read() == 0)
        return;
        
    if (trace_length >= config.max_trace_length) {
        shared_memory.set_termination(target_termination::boundary_condition_violation);
        exit(0);
    }
    
    if (!shared_memory.can_accept_bytes(branching_coverage_info::flattened_size())) {
        shared_memory.set_termination(target_termination::medium_overflow);
        exit(0);
    }

    location_id const id{ id_type, context_hashes.back() };
    natural_32_bit idx_to_br_instr = br_instr_trace_length;
    shared_memory << data_record_id::condition << id << direction << value << idx_to_br_instr << xor_like_branching_function << predicate;
    ++trace_length;
}

void fuzz_target::process_br_instr(location_id id, bool covered_branch) {
    if (stdin_model->num_bytes_read() == 0)
        return;

    if (br_instr_trace_length >= config.max_br_instr_trace_length) {
        shared_memory.set_termination(target_termination::boundary_condition_violation);
        exit(0);
    }

    if (!shared_memory.can_accept_bytes(br_instr_coverage_info::flattened_size())) {
        shared_memory.set_termination(target_termination::medium_overflow);
        exit(0);
    }

    shared_memory << data_record_id::br_instr << id << covered_branch;
    ++br_instr_trace_length;
}

void fuzz_target::process_call_begin(natural_32_bit  id) {
    if (context_hashes.size() >= config.max_stack_size) {
        shared_memory.set_termination(target_termination::boundary_condition_violation);
        exit(0);
    }

    if (context_hashes.size() == locations.size() + 1)
    {
        auto const  it_and_state = locations.insert(id);
        if (it_and_state.second)
            ::hash_combine(id, context_hashes.back());
        else
            id = context_hashes.back();
    }
    else
        id = context_hashes.back();

    context_hashes.push_back(id);
}


void fuzz_target::process_call_end(natural_32_bit const  id) {
    ASSUMPTION(
        context_hashes.size() > 1 &&
            [this](natural_32_bit  id) -> bool {
                if (context_hashes.size() != locations.size() + 1)
                    return true;
                ::hash_combine(id, context_hashes.at(context_hashes.size()-2));
                return id == context_hashes.back();
            }(id)
        );

    if (context_hashes.size() == locations.size() + 1)
    {
        auto const  num_deleted = locations.erase(id);
        INVARIANT(num_deleted == 1);
    }

    context_hashes.pop_back();
}

void fuzz_target::on_read(natural_8_bit* ptr, type_of_input_bits const type) {
    stdin_model->read(ptr, type, shared_memory);
}


void fuzz_target::on_write(natural_8_bit const*  ptr, type_of_input_bits const type) {
    stdout_model->write(ptr, type, shared_memory);
}


void fuzz_target::load_config() {
    config.load_target_config(shared_memory);
    stdin_model = get_stdin_models_map().at(config.stdin_model_name)(config.max_stdin_bytes);
    stdout_model = get_stdout_models_map().at(config.stdout_model_name)();
}

void fuzz_target::load_stdin() {
    stdin_model->load(shared_memory);
}

void fuzz_target::load_stdout() {
    stdout_model->load(shared_memory);
}


}