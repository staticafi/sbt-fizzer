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
#include <fuzzing/dump_testcomp.hpp>
#include <iostream>


void run(int argc, char* argv[])
{
    if (get_program_options()->has("list_fuzzers"))
    {
        for (auto const&  name_and_constructor : fuzzing::get_fuzzers_map())
            std::cout << name_and_constructor.first << std::endl;
        return;
    }
    if (!get_program_options()->has("fuzzer"))
    {
        std::cerr << "ERROR: no fuzzer is specified. Use --help.\n";
        return;
    }
    if (fuzzing::get_fuzzers_map().count(get_program_options()->value("fuzzer")) == 0UL)
    {
        std::cerr << "ERROR: passed unknown fuzzer name '" << get_program_options()->value("fuzzer") << "'. Use --list_fuzzers.\n";
        return;
    }
    const std::string& test_type = get_program_options()->value("test_type");
    if (test_type != "debug" && test_type != "sbt-eft" && test_type != "testcomp") {
        std::cerr << "ERROR: unknown output type specified. Use debug, sbt-eft or testcomp\n";
        return;
    }
    if (get_program_options()->value("path_to_client") == "")
    {
        std::cerr << "WARNING: empty path to client specified. The server will not automatically run fuzzing clients.\n";
    }

    fuzzing::termination_info const  terminator(
            std::max(0, get_program_options()->value_as_int("max_executions")),
            std::max(0, get_program_options()->value_as_int("max_seconds"))
            );

    std::string client_name = "client";
    if (!get_program_options()->value("path_to_client").empty()) {
        std::filesystem::path client_path(get_program_options()->value("path_to_client"));
        client_name = client_path.stem().string();
    }

    fuzzing::print_fuzzing_configuration(
            std::cout,
            get_program_options()->value("fuzzer"),
            client_name,
            terminator
            );

    iomodels::iomanager::instance().set_stdin(std::make_shared<iomodels::stdin_replay_bits_then_repeat_85>());
    iomodels::iomanager::instance().set_stdout(std::make_shared<iomodels::stdout_void>());
    iomodels::iomanager::instance().set_trace_max_size(std::stoul(get_program_options()->value("max_trace_size")));

    connection::server server(get_program_options()->value_as_int("port"), get_program_options()->value("path_to_client"));
    try {
        server.start();
    }
    catch (std::exception& e) {
        std::cerr << "ERROR: starting server\n" << e.what() << "\n";
        return;
    }

    fuzzing::analysis_outcomes const  results = server.run_fuzzing(get_program_options()->value("fuzzer"), terminator);

    server.stop();

    fuzzing::print_analysis_outcomes(std::cout, results, false);

    if (!get_program_options()->value("output_dir").empty())
    {
        std::filesystem::path output_dir = std::filesystem::absolute(get_program_options()->value("output_dir"));

        if (test_type == "testcomp") {
            output_dir /= "test-suite";
        }
        
        std::error_code  ec;
        if (!std::filesystem::create_directories(output_dir, ec) && ec)
            std::cerr << "ERROR: Failed to create/access the output directory:\n        " 
                      << output_dir << "\n"
                      << "       => No test was written to disk.\n";
        else
        {
            std::cout << "Saving tests under the output directory...";

            std::string test_name = "test";
            if (!get_program_options()->value("path_to_client").empty()) {
                test_name += "_for_" + client_name;
            }
            test_name += "_by_" + get_program_options()->value("fuzzer");

            if (test_type == "debug") {
                fuzzing::save_traces_with_coverage_infos_to_directory(
                    output_dir,
                    results.traces_forming_coverage,
                    true,
                    true,
                    test_name
                    );
            }
            else if (test_type == "testcomp") {
                fuzzing::save_testcomp_output(
                    output_dir, 
                    results.traces_forming_coverage,
                    test_name,
                    get_program_version(),
                    get_program_options()->value("path_to_client")
                    );
            }
            
            std::cout << "Done.\n" << std::flush;
        }
    }
}
