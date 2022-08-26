#include <fizz/program_info.hpp>
#include <fizz/program_options.hpp>
#include <benchmarks/benchmarks.hpp>
#include <connection/server_main.hpp>
#include <connection/client_main.hpp>
#include <fuzzing/analysis_outcomes.hpp>
#include <fuzzing/fuzzers_map.hpp>
#include <fuzzing/dump.hpp>
#include <iostream>


extern void test();


void run(int argc, char* argv[])
{
    if (get_program_options()->has("help"))
    {
        std::cout << get_program_options() << std::endl;
        return;
    }
    if (get_program_options()->has("version"))
    {
        std::cout << get_program_options()->value("version") << std::endl;
        return;
    }
    if (get_program_options()->has("test"))
    {
        if (get_program_options()->num_arguments() > 2UL)
            std::cout << "WARNING: In the '--test' mode passed options are ignored." << std::endl;
        test();
        return;
    }
    if (get_program_options()->has("list_fuzzers"))
    {
        for (auto const&  name_and_constructor : fuzzing::get_fuzzers_map())
            std::cout << name_and_constructor.first << std::endl;
        return;
    }
    if (get_program_options()->has("list_benchmarks"))
    {
        for (auto const&  name_and_driver : benchmarks::get_benchmarks_map())
            std::cout << name_and_driver.first << std::endl;
        return;
    }
    if (!get_program_options()->has("fuzzer"))
    {
        std::cout << "ERROR: no fuzzer is specified. Use --help." << std::endl;
        return;
    }
    if (fuzzing::get_fuzzers_map().count(get_program_options()->value("fuzzer")) == 0UL)
    {
        std::cout << "ERROR: passed unknown fuzzer name '" << get_program_options()->value("fuzzer") << "'. Use --list_fuzzers." << std::endl;
        return;
    }
    if (!get_program_options()->has("benchmark"))
    {
        std::cout << "ERROR: no benchmark is specified. Use --help." << std::endl;
        return;
    }
    if (benchmarks::get_benchmarks_map().count(get_program_options()->value("benchmark")) == 0UL)
    {
        std::cout << "ERROR: passed unknown benchmark name '" << get_program_options()->value("benchmark") << "'. Use --list_benchmarks." << std::endl;
        return;
    }

    fuzzing::termination_info const  terminator(
            std::max(0, std::stoi(get_program_options()->value("max_executions"))),
            std::max(0, std::stoi(get_program_options()->value("max_seconds")))
            );

    fuzzing::print_fuzzing_configuration(
            std::cout,
            get_program_options()->value("fuzzer"),
            get_program_options()->value("benchmark"),
            terminator
            );

    std::cout << "Fuzzing started..." << std::endl << std::flush;

    connection::client_main(get_program_options()->value("benchmark"));

    fuzzing::analysis_outcomes const  results = connection::server_main(get_program_options()->value("fuzzer"), terminator);

    fuzzing::print_analysis_outcomes(std::cout, results, false);

    if (!get_program_options()->value("output_dir").empty())
    {
        std::filesystem::path const  output_dir = std::filesystem::absolute(get_program_options()->value("output_dir"));
        std::error_code  ec;
        if (!std::filesystem::create_directories(output_dir, ec) && ec)
            std::cout << "ERROR: Failed to create/access the output directory:\n        " 
                      << output_dir << std::endl
                      << "       => No test was written to disk."
                      << std::flush;
        else
        {
            std::cout << "Saving tests under the output directory...";
            fuzzing::save_traces_with_coverage_infos_to_directory(
                    output_dir,
                    results.traces_forming_coverage,
                    true,
                    true,
                    "test_for_" + get_program_options()->value("benchmark") + "_by_" + get_program_options()->value("fuzzer")
                    );
            std::cout << "Done.\n" << std::flush;
        }
    }
}
