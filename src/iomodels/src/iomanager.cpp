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
    src >> uchr; info.direction = uchr != 0U;
    src >> info.value;
    src >> info.idx_to_br_instr;
    src >> uchr; info.xor_like_branching_function = uchr != 0U;
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
    src >> uchr; info.covered_branch = uchr != 0U;
    br_instr_trace.push_back(info);
    return true;
}

template bool iomanager::load_br_instr_trace_record(shared_memory&);
template bool iomanager::load_br_instr_trace_record(message&);


template <typename Medium>
void  iomanager::load_results(Medium& src) {
    TMPROF_BLOCK();
    bool  invalid_record_reached{ false };
    while (!invalid_record_reached && !src.exhausted()) {
        data_record_id id;
        src >> id;
        switch (id) {
            case data_record_id::condition: 
                invalid_record_reached = !load_trace_record(src);
                break;
            case data_record_id::br_instr:
                invalid_record_reached = !load_br_instr_trace_record(src);
                break;
            case data_record_id::stdin_bytes:
                invalid_record_reached = !get_stdin()->load_record(src);
                break;
            case data_record_id::termination:
                src >> termination;
                ASSUMPTION(valid_termination(termination));
                break;
            case data_record_id::invalid:
            default:
                INVARIANT(termination == target_termination::timeout);
                invalid_record_reached = true;
                break;
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



}
