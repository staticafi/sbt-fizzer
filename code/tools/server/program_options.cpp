#include <server/program_options.hpp>
#include <server/program_info.hpp>
#include <fuzzing/fuzzers_map.hpp>
#include <utility/assumptions.hpp>
#include <stdexcept>
#include <iostream>

program_options::program_options(int argc, char* argv[])
    : program_options_default(argc, argv)
{
    add_option("test", "Run all tests.", "0");

    add_option("list_fuzzers", "Prints fuzzers.", "0");

    add_option("output_dir", "A directory where to store generated tests.", "1");
    add_value("output_dir", ".");

    add_option("max_executions", "Max number of executions of the benchmark.", "1");
    add_value("max_executions", "1000000");

    add_option("max_seconds", "Max number of seconds for fuzzing the benchmark.", "1");
    add_value("max_seconds", "86400"); // 24h

    add_option("fuzzer", "A fuzzer to be used.", "1");
    if (fuzzing::get_fuzzers_map().count("fuzzhamm") != 0UL)
        add_value("fuzzer", "fuzzhamm");

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