#include <client/program_options.hpp>
#include <client/program_info.hpp>
#include <iomodels/iomanager.hpp>
#include <utility/assumptions.hpp>

program_options::program_options(int argc, char* argv[])
    : program_options_default(argc, argv)
{
    add_option("list_stdin_models", "Prints stdin models.", "0");
    add_option("list_stdout_models", "Prints stdout models.", "0");

    iomodels::iomanager::configuration const  io_cfg{};

    add_option("max_trace_length", "Max number of branchings in a trace.", "1");
    add_value("max_trace_length", std::to_string(io_cfg.max_trace_length));

    add_option("max_stack_size", "Max number of stack records during benchmark execution.", "1");
    add_value("max_stack_size", std::to_string(io_cfg.max_stack_size));

    add_option("max_stdin_bytes", "Max number of stdin bits read during benchmark execution.", "1");
    add_value("max_stdin_bytes", std::to_string(io_cfg.max_stdin_bytes));

    add_option("stdin_model", "The model of stdin to be used during the analysis.", "1");
    add_value("stdin_model", io_cfg.stdin_model_name);

    add_option("stdout_model", "The model of stdout to be used during the analysis.", "1");
    add_value("stdout_model", io_cfg.stdout_model_name);

    add_option("input", "Run the instrumented file with the specified hexadecimal input and output the trace.", "1");

    add_option("address", "The address of the SBT-Fizzer server in IPv4 dotted decimal form or IPv6 hexadecimal notation.", "1");
    add_value("address", "127.0.0.1");

    add_option("port", "The port of the SBT-Fizzer server.", "1");
    add_value("port", "42085");
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
