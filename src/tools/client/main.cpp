#include <client/program_options.hpp>
#include <utility/config.hpp>
#include <utility/timeprof.hpp>
#include <utility/log.hpp>
#include <client/program_info.hpp>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <iostream>

extern void run();

#if BUILD_RELEASE() == 1
static void save_crash_report(std::string const& crash_message)
{
    std::cerr << "ERROR: " << crash_message << "\n";
    std::ofstream  ofile( get_program_name() + "_CRASH.txt", std::ios_base::app );
    ofile << crash_message << "\n";
}
#endif

int main(int argc, char* argv[]) {
#if BUILD_RELEASE() == 1
    try
#endif
    {
        initialise_program_options(argc,argv);
        if (get_program_options()->helpMode())
            std::cout << get_program_options();
        else if (get_program_options()->versionMode())
            std::cout << get_program_version() << "\n";
        else
        {
            run();
        }
    }
#if BUILD_RELEASE() == 1
    catch(std::exception const& e)
    {
        try { save_crash_report(e.what()); } catch (...) {}
        return -1;
    }
    catch(...)
    {
        try { save_crash_report("Unknown exception was thrown."); } catch (...) {}
        return -2;
    }
#endif
    return 0;
}