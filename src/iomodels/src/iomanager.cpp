#include <iomodels/iomanager.hpp>
#include <iomodels/models_map.hpp>
#include <iomodels/stdin_replay_bytes_then_repeat_byte.hpp>
#include <iomodels/stdout_void.hpp>
#include <instrumentation/data_record_id.hpp>
#include <utility/hash_combine.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>

using namespace connection;
using namespace instrumentation;

namespace  iomodels {


iomanager::iomanager()
    : config{}
    , termination{ target_termination::normal }
    , trace()
    , br_instr_trace()
    , stdin_ptr(nullptr)
    , stdout_ptr(nullptr)
{}


iomanager&  iomanager::instance()
{
    static iomanager  man;
    return man;
}


void  iomanager::set_config(configuration const&  cfg)
{
    config = cfg;
    config.invalidate_shared_memory_size_cache();

    stdin_ptr = nullptr;
    stdout_ptr = nullptr;
}


void  iomanager::clear_trace()
{
    trace.clear();
}

void  iomanager::clear_br_instr_trace()
{
    br_instr_trace.clear();
}


template <typename Medium>
bool  iomanager::load_trace_record(Medium& src) {
    if (!src.can_deliver_bytes(branching_coverage_info::flattened_size()))
        return false;
    branching_coverage_info  info { invalid_location_id() };
    natural_8_bit uchr;
    src >> info.id;
    src >> uchr; info.direction = (uchr & 1U) != 0U;
    src >> info.value;
    src >> info.idx_to_br_instr;
    src >> uchr; info.xor_like_branching_function = (uchr & 1U) != 0U;
    src >> uchr; info.predicate = (BRANCHING_PREDICATE)uchr;
    info.num_input_bytes = (natural_32_bit)get_stdin()->get_bytes().size();
    trace.push_back(info);
    return true;
}

template bool iomanager::load_trace_record(shared_memory&);
template bool iomanager::load_trace_record(message&);


template <typename Medium>
bool  iomanager::load_br_instr_trace_record(Medium& src) {
    if (!src.can_deliver_bytes(br_instr_coverage_info::flattened_size()))
        return false;
    br_instr_coverage_info  info { invalid_location_id() };
    natural_8_bit uchr;
    src >> info.br_instr_id;
    src >> uchr; info.covered_branch = (uchr & 1U) != 0U;
    br_instr_trace.push_back(info);
    return true;
}

template bool iomanager::load_br_instr_trace_record(shared_memory&);
template bool iomanager::load_br_instr_trace_record(message&);


template <typename Medium>
void  iomanager::load_results(Medium& src) {
    TMPROF_BLOCK();

    ASSUMPTION(src.can_deliver_bytes(2UL));
    data_record_id id;
    src >> id;
    ASSUMPTION(id == data_record_id::termination);
    src >> termination;
    ASSUMPTION(valid_termination(termination));

    while (!src.exhausted()) {
        data_record_id id;
        src >> id;
        switch (id) {
            case data_record_id::condition: 
                if (load_trace_record(src) == false)
                    return; // Something went wrong => stop loading data.
                break;
            case data_record_id::br_instr:
                if (load_br_instr_trace_record(src) == false)
                    return; // Something went wrong => stop loading data.
                break;
            case data_record_id::stdin_bytes:
                if (get_stdin()->load_record(src) == false)
                    return; // Something went wrong => stop loading data.
                break;
            default:
                return; // Something went wrong => stop loading data.
        }
    }
}


template void iomanager::load_results(shared_memory&);
template void iomanager::load_results(message&);


stdin_base*  iomanager::get_stdin() const
{
    if (stdin_ptr == nullptr)
        stdin_ptr = get_stdin_models_map().at(config.stdin_model_name)(config.max_stdin_bytes);
    return stdin_ptr.get();
}



stdout_base*  iomanager::get_stdout() const
{
    if (stdout_ptr == nullptr)
        stdout_ptr = get_stdout_models_map().at(config.stdout_model_name)();
    return stdout_ptr.get();
}


stdin_base_ptr  iomanager::clone_stdin() const
{
    return get_stdin_models_map().at(config.stdin_model_name)(config.max_stdin_bytes);
}



stdout_base_ptr  iomanager::clone_stdout() const
{
    return get_stdout_models_map().at(config.stdout_model_name)();
}


}
