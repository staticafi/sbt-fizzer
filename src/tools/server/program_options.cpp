#include <server/program_options.hpp>
#include <server/program_info.hpp>
#include <iomodels/iomanager.hpp>
#include <fuzzing/termination_info.hpp>
#include <fuzzing/optimizer.hpp>
#include <utility/assumptions.hpp>

program_options::program_options(int argc, char* argv[])
    : program_options_default(argc, argv)
{
    add_option("list_stdin_models", "Prints stdin models.", "0");
    add_option("list_stdout_models", "Prints stdout models.", "0");

    add_option("output_dir", "A directory where to store generated tests.", "1");
    add_value("output_dir", ".");

    fuzzing::termination_info const  terminator{};

    add_option("max_executions", "Max number of executions for fuzzing the benchmark.", "1");
    add_value("max_executions", std::to_string(terminator.max_executions));

    add_option("max_seconds", "Max number of seconds for fuzzing the benchmark.", "1");
    add_value("max_seconds", std::to_string(terminator.max_seconds));

    iomodels::iomanager::configuration const  io_cfg{};

    add_option("max_trace_length", "Max number of branchings in a trace.", "1");
    add_value("max_trace_length", std::to_string(io_cfg.max_trace_length));

    add_option("max_stack_size", "Max number of stack records during benchmark execution.", "1");
    add_value("max_stack_size", std::to_string(io_cfg.max_stack_size));

    add_option("max_stdin_bytes", "Max number of stdin bits read during benchmark execution.", "1");
    add_value("max_stdin_bytes", std::to_string(io_cfg.max_stdin_bytes));

    add_option("max_exec_milliseconds", "Max number of milliseconds for benchmark execution.", "1");
    add_value("max_exec_milliseconds", std::to_string(io_cfg.max_exec_milliseconds));

    add_option("max_exec_megabytes", "Max number of mega bytes which can be allocated during benchmark execution.", "1");
    add_value("max_exec_megabytes", std::to_string(io_cfg.max_exec_megabytes));

    add_option("stdin_model", "The model of stdin to be used during the analysis.", "1");
    add_value("stdin_model", io_cfg.stdin_model_name);

    add_option("stdout_model", "The model of stdout to be used during the analysis.", "1");
    add_value("stdout_model", io_cfg.stdout_model_name);

    fuzzing::optimizer::configuration const  optimizer_config{};

    add_option("optimizer_max_seconds", "Max number of seconds for optimization of raw tests obtained from fuzzing.", "1");
    add_value("optimizer_max_seconds", std::to_string(optimizer_config.max_seconds));

    add_option("optimizer_max_trace_length", "Test suite optimizer option. Max number of branchings in a trace.", "1");
    add_value("optimizer_max_trace_length", std::to_string(optimizer_config.max_trace_length));

    add_option("optimizer_max_stdin_bytes", "Test suite optimizer option. Max number of stdin bits read during benchmark execution.", "1");
    add_value("optimizer_max_stdin_bytes", std::to_string(optimizer_config.max_stdin_bytes));

    add_option("path_to_client", "Path to client binary", "1");
    add_value("path_to_client", "");

    add_option("test_type", "Output type (native, testcomp)", "1");
    add_value("test_type", "native");

    add_option("path_to_program_ll", "Path to test.llvm to be used by JetKlee.", "1");
    add_value("path_to_program_ll", "");

    add_option("port", "Port the server will use", "1");
    add_value("port", "42085");

    add_option("kleeient_port", "Port the kleeient will use", "1");
    add_value("kleeient_port", "42086");

    add_option("debug_mode", "When specified, the fuzzer will generate debug data during the analysis.", "0");
<<<<<<< HEAD
    add_option("silent_mode", "Reduce the amount of messages printed to stdout.", "0");
=======

    add_option("jetklee_usage", "Jetklee usage policy (always, never, heuristic", "1");
    add_value("jetklee_usage", "heuristic");
>>>>>>> Make Jetklee usage configurable via option
}

static program_options_ptr  global_program_options;

void initialise_program_options(int argc, char* argv[])
{
    ASSUMPTION(!global_program_options.operator bool());
    global_program_options = program_options_ptr(new program_options(argc,argv));
}

program_options_ptr get_program_options()
{
    ASSUMPTION(global_program_options.operator bool());
    return global_program_options;
}

std::ostream& operator<<(std::ostream& ostr, program_options_ptr const& options)
{
    ASSUMPTION(options.operator bool());
    options->operator<<(ostr);
    return ostr;
}
