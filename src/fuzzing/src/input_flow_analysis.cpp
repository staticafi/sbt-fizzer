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
    extern_code(sala::ExecState*  state);
private:
    void read(std::size_t count);
    terminator_medium  medium_;
};


extern_code::extern_code(sala::ExecState* const  state)
    : sala::ExternCodeCStd{ state }
    , medium_{ state }
{
    register_code("__VERIFIER_nondet_bool", [this]() { this->read(sizeof(bool)); });
    register_code("__VERIFIER_nondet_char", [this]() { this->read(sizeof(std::int8_t)); });
    register_code("__VERIFIER_nondet_short", [this]() { this->read(sizeof(std::int16_t)); });
    register_code("__VERIFIER_nondet_int", [this]() { this->read(sizeof(std::int32_t)); });
    register_code("__VERIFIER_nondet_long", [this]() { this->read(sizeof(std::int32_t)); });
    register_code("__VERIFIER_nondet_longlong", [this]() { this->read(sizeof(std::int64_t)); });
    register_code("__VERIFIER_nondet_uchar", [this]() { this->read(sizeof(std::uint8_t)); });
    register_code("__VERIFIER_nondet_ushort", [this]() { this->read(sizeof(std::uint16_t)); });
    register_code("__VERIFIER_nondet_uint", [this]() { this->read(sizeof(std::uint32_t)); });
    register_code("__VERIFIER_nondet_ulong", [this]() { this->read(sizeof(std::uint32_t)); });
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
    if (!iomodels::iomanager::instance().get_stdin()->read_bytes(ptr, type, medium_))
    {
        state().set_stage(sala::ExecState::Stage::FINISHED);
        state().set_termination(
            sala::ExecState::Termination::ERROR,
            "input_flow_analysis[extern_code]",
            state().current_location_message() + ": Call to 'iomodels::iomanager::instance().get_stdin()->read_bytes()' has failed."
            );
    }
}


struct input_flow_analysis::input_flow : public sala::InputFlow
{
    input_flow(input_flow_analysis*  analysis, sala::ExecState*  state);
    bool  target_reached() const { return target_reached_; }
    branching_node*  get_last_visited_path_node() const
    { return path_index_ > 0UL && path_index_ <= path_nodes_.size() ? path_nodes_.at(path_index_ - 1UL) : nullptr; }

    std::size_t  path_length() const { return path_nodes_.size(); }
    std::size_t  path_index() const { return path_index_; }

private:
    void start_input_flow(std::size_t const count);
    void do_ret() override;

    input_flow_analysis*  analysis_;
    std::vector<branching_node*>  path_nodes_;
    std::vector<bool>  path_directions_;
    std::size_t  path_index_;
    bool  some_input_was_read_;
    bool  target_reached_;
};


input_flow_analysis::input_flow::input_flow(
        input_flow_analysis* const  analysis,
        sala::ExecState* const  state
        )
    : sala::InputFlow{ state }
    , analysis_{ analysis }
    , path_nodes_{}
    , path_directions_{}
    , path_index_{ 0ULL }
    , some_input_was_read_{ false }
    , target_reached_{ false }
{
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_bool, this->start_input_flow(sizeof(bool)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_char, this->start_input_flow(sizeof(std::int8_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_short, this->start_input_flow(sizeof(std::int16_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_int, this->start_input_flow(sizeof(std::int32_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_long, this->start_input_flow(sizeof(std::int32_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_longlong, this->start_input_flow(sizeof(std::int64_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_uchar, this->start_input_flow(sizeof(std::uint8_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_ushort, this->start_input_flow(sizeof(std::uint16_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_uint, this->start_input_flow(sizeof(std::uint32_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_ulong, this->start_input_flow(sizeof(std::uint32_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_ulonglong, this->start_input_flow(sizeof(std::uint64_t)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_float, this->start_input_flow(sizeof(float)) );
    REGISTER_EXTERN_FUNCTION_PROCESSOR(__VERIFIER_nondet_double, this->start_input_flow(sizeof(double)) );

    for (branching_node* n = analysis_->node; n != nullptr; n = n->get_predecessor())
        path_nodes_.push_back(n);
    std::reverse(path_nodes_.begin(), path_nodes_.end());
    for (std::size_t i = 1ULL; i < path_nodes_.size(); ++i)
        path_directions_.push_back(path_nodes_.at(i - 1ULL)->successor_direction(path_nodes_.at(i)));
}


void input_flow_analysis::input_flow::start_input_flow(std::size_t const count)
{
    std::size_t desc{ iomodels::iomanager::instance().get_stdin()->num_bytes_read() - count };
    sala::MemPtr ptr{ parameters().front().read<sala::MemPtr>() };
    for (std::size_t i = 0ULL; i != count; ++i, ++desc)
        start(ptr + i, (sala::InputFlow::InputDescriptor)desc);
    some_input_was_read_ = true;
}


void input_flow_analysis::input_flow::do_ret()
{
    if (some_input_was_read_ && state().current_function().name() == "__sbt_fizzer_process_condition")
    {
        INVARIANT(path_index_ < path_nodes_.size());

        if (path_nodes_.at(path_index_)->get_location_id().id != parameters().front().read<instrumentation::location_id>().id)
        {
            auto const& expected{ path_nodes_.at(path_index_)->get_location_id() };
            auto const obtained{ parameters().front().read<instrumentation::location_id>() };
            state().set_stage(sala::ExecState::Stage::FINISHED);
            state().set_termination(
                sala::ExecState::Termination::ERROR,
                "input_flow_analysis[extern_code]",
                "Execution diverged from the expected path in the tree."
                    " At path index " + std::to_string(path_index_) + "/" + std::to_string(path_nodes_.size() - 1UL) + ": Unexpected location ID."
                    " [Expected: " + std::to_string(expected.id) +
                    ", obtained: " + std::to_string(obtained.id) + "]"
                );
            return;
        }

        if (path_index_ < path_directions_.size() && path_directions_.at(path_index_) != parameters().at(1).read<bool>())
        {
            bool const expected{ path_directions_.at(path_index_) };
            std::stringstream obtained; obtained << (integer_32_bit)parameters().at(1).read<natural_8_bit>();
            auto const& loc{ path_nodes_.at(path_index_)->get_location_id() };
            state().set_stage(sala::ExecState::Stage::FINISHED);
            state().set_termination(
                sala::ExecState::Termination::ERROR,
                "input_flow_analysis[extern_code]",
                "Execution diverged from the expected path in the tree."
                    " At path index " + std::to_string(path_index_) + "/" + std::to_string(path_nodes_.size() - 1UL) + ": Unexpected direction taken."
                    " [Expected: " + std::to_string(expected) +
                    ", obtained: " + obtained.str() + "]"
                    "[NOTE: location ID: " + std::to_string(loc.id) + "]"
                );
            return;
        }

        branching_node* const  current_node{ path_nodes_.at(path_index_) };
        sala::MemPtr ptr{ parameters().at(2).start() };
        for (std::size_t i = 0ULL; i != sizeof(branching_function_value_type); ++i)
            for (auto const& desc : read(ptr + i)->descriptors())
                for (std::size_t j = 0ULL; j != 8ULL; ++j)
                    if (current_node->insert_sensitive_stdin_bit((stdin_bit_index)(8ULL * desc + j)))
                        analysis_->changed_nodes.insert(current_node);

        ++path_index_;
        if (path_index_ == path_nodes_.size())
        {
            state().set_stage(sala::ExecState::Stage::FINISHED);
            state().set_termination(
                sala::ExecState::Termination::NORMAL,
                "input_flow_analysis[extern_code]",
                "Execution reached the last node of the expected path in the tree."
                );

            target_reached_ = true;

            return;
        }
    }
    sala::InputFlow::do_ret();
}


input_flow_analysis::input_flow_analysis(sala::Program const* const sala_program_ptr)
    : state{ READY }
    , program_ptr{ sala_program_ptr }
    , trace{ nullptr }
    , node{ nullptr }
    , execution_id{ 0 }
    , changed_nodes{}
    , last_visited_path_node{ nullptr }
    , statistics{}
{}


void  input_flow_analysis::start(branching_node* const  node_ptr, natural_32_bit const  execution_id_)
{
    ASSUMPTION(is_ready());
    ASSUMPTION(node_ptr != nullptr && node_ptr->get_best_stdin() && node_ptr->get_best_trace() != nullptr);
    ASSUMPTION(node_ptr->get_best_trace()->size() > node_ptr->get_trace_index());
    ASSUMPTION(
        [node_ptr]() -> bool {
            branching_node*  n = node_ptr;
            for (trace_index_type  i = n->get_trace_index() + 1U; i > 0U; --i, n = n->get_predecessor())
            {
                if (n == nullptr || n->get_location_id() != node_ptr->get_best_trace()->at(i - 1U).id)
                    return false;
                if (i > 1U && n->get_predecessor()->successor_direction(n) != node_ptr->get_best_trace()->at(i - 2U).direction)
                    return false;
            }
            return n == nullptr;
        }()
        );

    state = BUSY;
    trace = node_ptr->get_best_trace();
    node = node_ptr;
    execution_id = execution_id_;
    changed_nodes.clear();
    last_visited_path_node = nullptr;

    ++statistics.start_calls;
}


void  input_flow_analysis::stop()
{
    if (!is_busy())
        return;

    for (branching_node* n = node; n != nullptr; n = n->get_predecessor())
    {
        if (!n->was_sensitivity_performed())
            changed_nodes.insert(n);
        n->set_sensitivity_performed(execution_id);
    }

    state = READY;
    ++statistics.stop_calls;
}


void  input_flow_analysis::compute_sensitive_bits(float_64_bit const  remaining_seconds)
{
    TMPROF_BLOCK();

    if (!is_busy())
        return;

    if (program_ptr == nullptr)
    {
        stop();
        return;
    }

    vecu8 stdin_bytes;
    bits_to_bytes(node->get_best_stdin()->bits, stdin_bytes);

    iomodels::iomanager::instance().get_stdin()->clear();
    iomodels::iomanager::instance().get_stdout()->clear();
    iomodels::iomanager::instance().get_stdin()->set_bytes(stdin_bytes);

    std::chrono::system_clock::time_point const  start_time = std::chrono::system_clock::now();

    sala::ExecState  state{ program_ptr, iomodels::iomanager::instance().get_config().max_exec_megabytes * 1024ULL * 1024ULL };
    sala::Sanitizer  sanitizer{ &state };
    input_flow  flow{ this, &state };
    extern_code  externals{ &state };
    sala::Interpreter  interpreter{ &state, &externals, { &sanitizer, &flow } };

    float_64_bit constexpr native_vs_interpreter_speed_ratio{ 10.0 };
    float_64_bit const  run_time{
            std::min(
                remaining_seconds,
                native_vs_interpreter_speed_ratio * (iomodels::iomanager::instance().get_config().max_exec_milliseconds * 0.001)
                )
    };

    interpreter.run(run_time);

    last_visited_path_node = flow.get_last_visited_path_node();

    if (last_visited_path_node != nullptr)
    {
        std::pair<natural_32_bit,trace_index_type> const key{ last_visited_path_node->get_trace_index(), last_visited_path_node->get_num_stdin_bytes() };
        float_64_bit const  value = std::chrono::duration<float_64_bit>(std::chrono::system_clock::now() - start_time).count();
        //statistics.complexity[key].insert(value);
    }

    if (!flow.target_reached())
    {
        statistics.errors.insert(make_problem_message(state.report(
            (state.error_message().empty() ? state.current_location_message() : " ") +
            "At path index " + std::to_string(flow.path_index()) + "/" + std::to_string(flow.path_length() - 1UL) +
            ": Unexpected divergence from the path."
            )));
        ++statistics.num_failures;
    }

    for (std::string const&  warning : state.warnings())
        statistics.warnings.insert(make_problem_message("\"" + warning + "\""));

    stop();
}


std::string  input_flow_analysis::make_problem_message(std::string const&  content) const
{
    std::stringstream  sstr;
    sstr << "{ "
         << "\"loc_id\": \"" << node->get_location_id() << "\""
         << ", "
         << "\"details\": " << content
         << " }"
         ;
    return sstr.str();

}


}
