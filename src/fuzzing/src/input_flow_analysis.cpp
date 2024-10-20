#include <fuzzing/input_flow_analysis.hpp>
#include <fuzzing/progress_recorder.hpp>
#include <iomodels/iomanager.hpp>
#include <sala/interpreter.hpp>
#include <sala/sanitizer.hpp>
#include <sala/input_flow.hpp>
#include <sala/extern_code_cstd.hpp>
#include <utility/assumptions.hpp>
#include <utility/invariants.hpp>
#include <utility/timeprof.hpp>
#include <vector>
#include <algorithm>
#include <sstream>
#include <chrono>

namespace  fuzzing {


struct terminator_medium : public connection::medium
{
    terminator_medium(sala::ExecState* state) : connection::medium{}, state_{ state } {}
    void set_termination(instrumentation::target_termination  termination) override;
private:
    sala::ExecState* state_;
};


void terminator_medium::set_termination(instrumentation::target_termination  termination)
{
    std::string  message;
    switch (termination)
    {
        case instrumentation::target_termination::normal:
            message = state_->make_error_message("normal");
            break;
        case instrumentation::target_termination::crash:
            message = state_->make_error_message("crash");
            break;
        case instrumentation::target_termination::timeout:
            message = state_->make_error_message("timeout");
            break;
        case instrumentation::target_termination::boundary_condition_violation:
            message = state_->make_error_message("boundary_condition_violation");
            break;
        case instrumentation::target_termination::medium_overflow:
            message = state_->make_error_message("medium_overflow");
            break;
        default: UNREACHABLE(); break;
    }
    state_->set_stage(sala::ExecState::Stage::FINISHED);
    state_->set_termination(
        sala::ExecState::Termination::ERROR,
        "input_flow_analysis[terminator_medium]",
        message
        );
}


struct extern_code : public sala::ExternCodeCStd
{
    extern_code(sala::ExecState*  state, input_flow_analysis::io_models_setup const* io_setup_ptr_);
    input_flow_analysis::io_models_setup const&  io_setup() const { return *io_setup_ptr; }
private:
    void read(std::size_t count);
    terminator_medium  medium_;
    input_flow_analysis::io_models_setup const* io_setup_ptr;
};


extern_code::extern_code(sala::ExecState* const  state, input_flow_analysis::io_models_setup const* const io_setup_ptr_)
    : sala::ExternCodeCStd{ state }
    , medium_{ state }
    , io_setup_ptr{ io_setup_ptr_ }
{
    register_code("__VERIFIER_nondet_bool", [this]() { this->read(sizeof(bool)); });
    register_code("__VERIFIER_nondet_char", [this]() { this->read(sizeof(std::int8_t)); });
    register_code("__VERIFIER_nondet_short", [this]() { this->read(sizeof(std::int16_t)); });
    register_code("__VERIFIER_nondet_int", [this]() { this->read(sizeof(std::int32_t)); });
    register_code("__VERIFIER_nondet_long", [this]() { this->read(program().num_cpu_bits() == 32U ? sizeof(std::int32_t) : sizeof(std::int64_t)); });
    register_code("__VERIFIER_nondet_longlong", [this]() { this->read(sizeof(std::int64_t)); });
    register_code("__VERIFIER_nondet_uchar", [this]() { this->read(sizeof(std::uint8_t)); });
    register_code("__VERIFIER_nondet_ushort", [this]() { this->read(sizeof(std::uint16_t)); });
    register_code("__VERIFIER_nondet_uint", [this]() { this->read(sizeof(std::uint32_t)); });
    register_code("__VERIFIER_nondet_ulong", [this]() { this->read(program().num_cpu_bits() == 32U ? sizeof(std::uint32_t) : sizeof(std::uint64_t)); });
    register_code("__VERIFIER_nondet_ulonglong", [this]() { this->read(sizeof(std::uint64_t)); });
    register_code("__VERIFIER_nondet_float", [this]() { this->read(sizeof(float)); });
    register_code("__VERIFIER_nondet_double", [this]() { this->read(sizeof(double)); });
}


void extern_code::read(std::size_t const count)
{
    type_of_input_bits  type;
    switch (count)
    {
        case 1ULL: type = type_of_input_bits::UNTYPED8; break;
        case 2ULL: type = type_of_input_bits::UNTYPED16; break;
        case 4ULL: type = type_of_input_bits::UNTYPED32; break;
        case 8ULL: type = type_of_input_bits::UNTYPED64; break;
        default: UNREACHABLE(); break;
    }
    sala::MemPtr const ptr{ parameters().front().read<sala::MemPtr>() };
    if (!io_setup().stdin_ptr->read_bytes(ptr, type, medium_))
    {
        state().set_stage(sala::ExecState::Stage::FINISHED);
        state().set_termination(
            sala::ExecState::Termination::ERROR,
            "input_flow_analysis[extern_code]",
            state().current_location_message() + ": Call to 'io_setup().stdin_ptr->read_bytes()' has failed."
            );
    }
}


struct input_flow_analysis::input_flow : public sala::InputFlow
{
    input_flow(input_flow_analysis*  analysis, sala::ExecState*  state);
    computation_io_data&  data() { return analysis_->data(); }
    io_models_setup const&  io_setup() const { return analysis_->io_setup(); }

private:
    void start_input_flow(std::size_t const count);
    void do_ret() override;

    input_flow_analysis*  analysis_;
    bool  some_input_was_read_;
};


input_flow_analysis::input_flow::input_flow(
        input_flow_analysis* const  analysis,
        sala::ExecState* const  state
        )
    : sala::InputFlow{ state }
    , analysis_{ analysis }
    , some_input_was_read_{ false }
{
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_bool, this->start_input_flow(sizeof(bool)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_char, this->start_input_flow(sizeof(std::int8_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_short, this->start_input_flow(sizeof(std::int16_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_int, this->start_input_flow(sizeof(std::int32_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_long, this->start_input_flow(program().num_cpu_bits() == 32U ? sizeof(std::int32_t) : sizeof(std::int64_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_longlong, this->start_input_flow(sizeof(std::int64_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_uchar, this->start_input_flow(sizeof(std::uint8_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_ushort, this->start_input_flow(sizeof(std::uint16_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_uint, this->start_input_flow(sizeof(std::uint32_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_ulong, this->start_input_flow(program().num_cpu_bits() == 32U ? sizeof(std::uint32_t) : sizeof(std::uint64_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_ulonglong, this->start_input_flow(sizeof(std::uint64_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_float, this->start_input_flow(sizeof(float)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_double, this->start_input_flow(sizeof(double)) );
}


void input_flow_analysis::input_flow::start_input_flow(std::size_t const count)
{
    std::size_t desc{ io_setup().stdin_ptr->num_bytes_read() - count };
    sala::MemPtr ptr{ parameters().front().read<sala::MemPtr>() };
    for (std::size_t i = 0ULL; i != count; ++i, ++desc)
        start(ptr + i, (sala::InputFlow::InputDescriptor)desc);
    some_input_was_read_ = true;
}


void input_flow_analysis::input_flow::do_ret()
{
    if (some_input_was_read_ && state().current_function().name() == "__sbt_fizzer_process_condition")
    {
        INVARIANT(data().sensitive_bits.size() < data().trace_size);

        trace_index_type const  path_index{ (trace_index_type)data().sensitive_bits.size() };
        branching_coverage_info const&  branching{ data().trace_ptr->at(path_index) };

        if (branching.id.id != parameters().front().read<instrumentation::location_id>().id)
        {
            auto const& expected{ branching.id };
            auto const obtained{ parameters().front().read<instrumentation::location_id>() };
            state().set_stage(sala::ExecState::Stage::FINISHED);
            state().set_termination(
                sala::ExecState::Termination::ERROR,
                "input_flow_analysis[extern_code]",
                "Execution diverged from the expected path in the tree."
                    " At path index " + std::to_string(path_index) + "/" + std::to_string(data().trace_size - 1U) + ": Unexpected location ID."
                    " [Expected: " + std::to_string(expected.id) +
                    ", obtained: " + std::to_string(obtained.id) + "]"
                );
            return;
        }

        if (path_index + 1U < data().trace_size && branching.direction != parameters().at(1).read<bool>())
        {
            bool const expected{ branching.direction };
            std::stringstream obtained; obtained << (integer_32_bit)parameters().at(1).read<natural_8_bit>();
            auto const& loc{ branching.id };
            state().set_stage(sala::ExecState::Stage::FINISHED);
            state().set_termination(
                sala::ExecState::Termination::ERROR,
                "input_flow_analysis[extern_code]",
                "Execution diverged from the expected path in the tree."
                    " At path index " + std::to_string(path_index) + "/" + std::to_string(data().trace_size - 1U) + ": Unexpected direction taken."
                    " [Expected: " + std::to_string(expected) +
                    ", obtained: " + obtained.str() + "]"
                    "[NOTE: location ID: " + std::to_string(loc.id) + "]"
                );
            return;
        }

        data().sensitive_bits.push_back({});
        std::unordered_set<stdin_bit_index>&  sensitive_bits{ data().sensitive_bits.back() };
        sala::MemPtr ptr{ parameters().at(2).start() };
        for (std::size_t i = 0ULL; i != sizeof(branching_function_value_type); ++i)
            for (auto const& desc : read(ptr + i)->descriptors())
                for (std::size_t j = 0ULL; j != 8ULL; ++j)
                    sensitive_bits.insert(8ULL * desc + j);

        if (path_index + 1U == data().trace_size)
        {
            state().set_stage(sala::ExecState::Stage::FINISHED);
            state().set_termination(
                sala::ExecState::Termination::NORMAL,
                "input_flow_analysis[extern_code]",
                "Execution reached the last node of the expected path in the tree."
                );

            return;
        }
    }
    sala::InputFlow::do_ret();
}


input_flow_analysis::input_flow_analysis(sala::Program const* const sala_program_ptr, io_models_setup const* const io_setup_ptr_)
    : program_ptr{ sala_program_ptr }
    , io_setup_ptr{ io_setup_ptr_ }
    , data_ptr{ nullptr }
    , statistics{}
{}


void  input_flow_analysis::run(computation_io_data* const  data_ptr_)
{
    ASSUMPTION(
        data_ptr_->input_ptr != nullptr &&
        data_ptr_->trace_ptr != nullptr &&
        data_ptr_->trace_size > 0U && data_ptr_->trace_size <= (trace_index_type)data_ptr_->trace_ptr->size()
        );

    data_ptr = data_ptr_;
    data().sensitive_bits.clear();

    if (program_ptr == nullptr)
        return;

    vecu8 stdin_bytes;
    bits_to_bytes(data().input_ptr->bits, stdin_bytes);
    io_setup().stdin_ptr->clear();
    io_setup().stdout_ptr->clear();
    io_setup().stdin_ptr->set_bytes(stdin_bytes);

    std::chrono::system_clock::time_point const  start_time = std::chrono::system_clock::now();

    sala::ExecState  state{ program_ptr, io_setup().io_config.max_exec_megabytes * 1024ULL * 1024ULL };
    sala::Sanitizer  sanitizer{ &state };
    input_flow  flow{ this, &state };
    extern_code  externals{ &state, &io_setup() };
    sala::Interpreter  interpreter{ &state, &externals, { &sanitizer, &flow } };

    interpreter.run(data().remaining_seconds);

    INVARIANT(data().sensitive_bits.size() <= data().trace_size);

    if (!data().sensitive_bits.empty())
    {
        std::size_t const  last_index{ data().sensitive_bits.size() - 1ULL };
        branching_coverage_info const&  last_branching{ data().trace_ptr->at(last_index) };
        std::pair<natural_32_bit,trace_index_type> const key{ last_index, last_branching.num_input_bytes };
        float_64_bit const  value = std::chrono::duration<float_64_bit>(std::chrono::system_clock::now() - start_time).count();
        //statistics.complexity[key].insert(value);
    }

    auto const& make_problem_message = [this](std::string const&  content) {
        std::stringstream  sstr;
        sstr << "{ "
            << "\"loc_id\": \"" << data().trace_ptr->at(data().trace_size - 1U).id << "\""
            << ", "
            << "\"details\": " << content
            << " }"
            ;
        return sstr.str();
    };

    if (data().sensitive_bits.size() < data().trace_size)
    {
        std::size_t const  divergence_index{ data().sensitive_bits.empty() ? 0ULL : data().sensitive_bits.size() - 1ULL };
        statistics.errors.insert(make_problem_message(state.report(
            (state.error_message().empty() ? state.current_location_message() : " ") +
            "At path index " + std::to_string(divergence_index) + "/" + std::to_string(data().trace_size - 1UL) +
            ": Unexpected divergence from the path."
            )));
        ++statistics.num_failures;
    }
    else
        ++statistics.num_successes;

    for (std::string const&  warning : state.warnings())
        statistics.warnings.insert(make_problem_message("\"" + warning + "\""));
}


}
