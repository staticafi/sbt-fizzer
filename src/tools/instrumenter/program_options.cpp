#include <instrumenter/program_options.hpp>
#include <instrumenter/program_info.hpp>
#include <utility/assumptions.hpp>

program_options::program_options(int argc, char* argv[])
    : program_options_default(argc, argv)
{
    add_option("input", "Pathname to the input .ll file.", "1");
    add_option("output", "Pathname to the output .ll file where the instrumented version of the input file will be stored.", "1");
    add_option("br_too", "Instrument also conditional 'br' instructions. This is necessary only for the communication with JetKlee.", "0");
    add_option("save_mapping", "When specified, there will be saved JSON files describing mapping from the instrumented "
               "instructions to the original C file. NOTE: Requires C file to be compiled with debug information.", "0");
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
