#include <fizz/program_info.hpp>
#include <fizz/program_options.hpp>
#include <utility/config.hpp>
#include <utility/timeprof.hpp>
#include <utility/log.hpp>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <iostream>
//#if COMPILER() == COMPILER_VC()
//#   pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup") 
//#endif

extern void run(int argc, char* argv[]);

#if BUILD_RELEASE() == 1
static void save_crash_report(std::string const& crash_message)
{
    std::cout << "ERROR: " << crash_message << "\n";
    std::ofstream  ofile( get_program_name() + "_CRASH.txt", std::ios_base::app );
    ofile << crash_message << "\n";
}
#endif

int main(int argc, char* argv[])
{
#if BUILD_RELEASE() == 1
    try
#endif
    {
        LOG_INITIALISE(get_program_name(), LSL_INFO);
        initialise_program_options(argc,argv);
        if (get_program_options()->helpMode())
            std::cout << get_program_options();
        else if (get_program_options()->versionMode())
            std::cout << get_program_version() << "\n";
        else
        {
            run(argc,argv);
            TMPROF_PRINT_TO_FILE(get_program_name(),true);
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
