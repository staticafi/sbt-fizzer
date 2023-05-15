#include <instrumenter/program_info.hpp>

std::string  get_program_name()
{
    return "instrumenter";
}

std::string  get_program_version()
{
    return "0.1";
}

std::string  get_program_description()
{
    return "Provides instrumentation of a *.ll file.\n";
}
