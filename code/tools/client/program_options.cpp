#include <fizz/program_options.hpp>
#include <fizz/program_info.hpp>
#include <fuzzing/fuzzers_map.hpp>
#include <benchmarks/benchmarks.hpp>
#include <utility/assumptions.hpp>
#include <stdexcept>
#include <iostream>

program_options::program_options(int argc, char* argv[])
    : program_options_default(argc, argv)
{
    add_option("input", "Run the instrumented file with the specified hexadecimal input and output the trace", "1");

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
