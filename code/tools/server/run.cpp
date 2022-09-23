#include <boost/asio.hpp>

#include <server/program_info.hpp>
#include <server/program_options.hpp>
#include <connection/server.hpp>
#include <iomodels/iomanager.hpp>
#include <iomodels/stdin_replay_bits_then_repeat_85.hpp>
#include <iomodels/stdout_void.hpp>
#include <fuzzing/analysis_outcomes.hpp>
#include <fuzzing/fuzzers_map.hpp>
#include <fuzzing/dump.hpp>
#include <iostream>


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
    if (get_program_options()->has("list_fuzzers"))
    {
        for (auto const&  name_and_constructor : fuzzing::get_fuzzers_map())
            std::cout << name_and_constructor.first << std::endl;
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
    if (get_program_options()->value("path_to_client") == "")
    {
        std::cout << "WARNING: empty path to client specified. The server will not automatically run fuzzing clients." << std::endl;
    }

    fuzzing::termination_info const  terminator(
            std::max(0, get_program_options()->value_as_int("max_executions")),
            std::max(0, get_program_options()->value_as_int("max_seconds"))
            );

    fuzzing::print_fuzzing_configuration(
            std::cout,
            get_program_options()->value("fuzzer"),
            "client",
            terminator
            );

    connection::server server(42085, get_program_options()->value("path_to_client"));
    try {
        server.start();
    }
    catch (std::exception& e) {
        std::cout << "ERROR: starting server\n";
        std::cout << e.what() << std::endl;
        return;
    }

    iomodels::iomanager::instance().set_stdin(std::make_shared<iomodels::stdin_replay_bits_then_repeat_85>());
    iomodels::iomanager::instance().set_stdout(std::make_shared<iomodels::stdout_void>());

    fuzzing::analysis_outcomes const  results = server.run_fuzzing(get_program_options()->value("fuzzer"), terminator);

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
                    "test_by_" + get_program_options()->value("fuzzer")
                    );
            std::cout << "Done.\n" << std::flush;
        }
    }
}
