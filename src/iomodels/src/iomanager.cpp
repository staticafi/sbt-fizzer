#include <iomodels/iomanager.hpp>
#include <iomodels/stdin_replay_bits_then_repeat_85.hpp>
#include <iomodels/stdout_void.hpp>
#include <iomodels/ioexceptions.hpp>
#include <utility/hash_combine.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <iostream>
#include <iostream>

namespace  iomodels {


iomanager::iomanager()
    : config{}
    , trace()
    , br_instr_trace()
    , context_hashes{ 0U }
    , locations{}
    , stdin_ptr(nullptr)
    , stdout_ptr(nullptr)
{
    INVARIANT(context_hashes.size() == locations.size() + 1);
}


iomanager&  iomanager::instance()
{
    static iomanager  man;
    return man;
}


void  iomanager::set_config(configuration const&  cfg)
{
    config = cfg;
    
    stdin_ptr = nullptr;
}


void  iomanager::save_termination(connection::message&  ostr) const
{
    ostr << termination;
}


void  iomanager::load_termination(connection::message&  istr)
{
    istr >> termination;
}


void  iomanager::crash(natural_32_bit const  loc_id)
{
    throw execution_crashed("The program execution crashed at line " + std::to_string(loc_id) + '.');    
}


void  iomanager::clear_trace()
{
    trace.clear();
    context_hashes.clear();
    context_hashes.push_back(0U);
    locations.clear();
    INVARIANT(context_hashes.size() == locations.size() + 1);
}

void  iomanager::clear_br_instr_trace()
{
    br_instr_trace.clear();
}


void  iomanager::save_br_instr_trace(connection::message&  ostr) const 
{
    ostr << (natural_32_bit)br_instr_trace.size();
    for (br_instr_coverage_info const&  info : br_instr_trace) 
    {
        ostr << info.br_instr_id << info.covered_branch;
    }
}


void  iomanager::load_br_instr_trace(connection::message&  istr) 
{
    natural_32_bit  n;
    istr >> n;
    for (natural_32_bit i = 0; i < n; ++i)
    {
        br_instr_coverage_info  info(invalid_location_id());
        istr >> info.br_instr_id;
        istr >> info.covered_branch;
        br_instr_trace.push_back(info);
    }
}


void  iomanager::save_trace(connection::message&  ostr) const
{
    ostr << (natural_32_bit)trace.size();
    for (branching_coverage_info const&  info : trace)
        ostr << info.id
             << info.direction
             << info.value
             ;
}


void  iomanager::load_trace(connection::message&  istr)
{
    natural_32_bit  n;
    istr >> n;
    for (natural_32_bit  i = 0ULL; i < n; ++i)
    {
        branching_coverage_info  info { invalid_location_id() };
        istr >> info.id;
        istr >> info.direction;
        istr >> info.value;
        trace.push_back(info);
    }
}


void  iomanager::branching(instrumentation::branching_coverage_info const&  info)
{
    if (get_stdin()->num_bits_read() == 0)
        return;
    if (trace.size() >= config.max_trace_length)
        throw boundary_condition_violation("The max trace length exceeded.");

    trace.push_back(info);
    trace.back().id.context_hash = context_hashes.back();
    trace.back().idx_to_br_instr = (natural_32_bit)br_instr_trace.size();
}


void iomanager::br_instr(instrumentation::br_instr_coverage_info const&  info)
{
    if (get_stdin()->num_bits_read() == 0)
        return;
    br_instr_trace.push_back(info);
}


void  iomanager::call_begin(natural_32_bit  id)
{
    if (context_hashes.size() >= config.max_stack_size)
        throw boundary_condition_violation("The max stack size exceeded.");

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


void  iomanager::call_end(natural_32_bit const  id)
{
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


std::unordered_map<std::string, std::function<stdin_base_ptr(stdin_base::bit_count_type)> > const&  iomanager::get_stdin_models_map()
{
    static std::unordered_map<std::string, std::function<stdin_base_ptr(stdin_base::bit_count_type)> > const  models {
        { "stdin_replay_bits_then_repeat_85", [](stdin_base::bit_count_type const  max_bits){
            return std::make_shared<stdin_replay_bits_then_repeat_85>(max_bits); } }
    };
    return models;
}


stdin_base_ptr  iomanager::get_stdin() const
{
    if (stdin_ptr == nullptr)
        stdin_ptr = get_stdin_models_map().at(config.stdin_model_name)(config.max_stdin_bits);
    return stdin_ptr;
}


void  iomanager::clear_stdin()
{
    get_stdin()->clear();
}


void  iomanager::save_stdin(connection::message&  ostr) const
{
    get_stdin()->save(ostr);
}


void  iomanager::load_stdin(connection::message&  istr)
{
    get_stdin()->load(istr);
}


void  iomanager::read_stdin(location_id const  id, natural_8_bit* ptr, natural_8_bit const  count)
{
    get_stdin()->read(id, ptr, count);
}


std::unordered_map<std::string, std::function<stdout_base_ptr()> > const&  iomanager::get_stdout_models_map()
{
    static std::unordered_map<std::string, std::function<stdout_base_ptr()> > const  models {
        { "stdout_void", [](){ return std::make_shared<stdout_void>(); } }
    };
    return models;
}


stdout_base_ptr  iomanager::get_stdout() const
{
    if (stdout_ptr == nullptr)
        stdout_ptr = get_stdout_models_map().at(config.stdout_model_name)();
    return stdout_ptr;
}


void  iomanager::clear_stdout()
{
    get_stdout()->clear();
}


void  iomanager::save_stdout(connection::message&  ostr) const
{
    get_stdout()->save(ostr);
}


void  iomanager::load_stdout(connection::message&  istr)
{
    get_stdout()->load(istr);
}


void  iomanager::write_stdout(location_id const  id, natural_8_bit const* ptr, natural_8_bit const  count)
{
    get_stdout()->write(id, ptr, count);
}


}
