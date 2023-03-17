#include <server/program_info.hpp>
#include <server/program_options.hpp>
#include <connection/server.hpp>
#include <iomodels/iomanager.hpp>
#include <fuzzing/analysis_outcomes.hpp>
#include <fuzzing/fuzzing_loop.hpp>
#include <fuzzing/dump.hpp>
#include <fuzzing/dump_testcomp.hpp>
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
    if (get_program_options()->has("list_stdin_models"))
    {
        for (auto const&  name_and_constructor : iomodels::iomanager::get_stdin_models_map())
            std::cout << name_and_constructor.first << std::endl;
        return;
    }
    if (get_program_options()->has("list_stdout_models"))
    {
        for (auto const&  name_and_constructor : iomodels::iomanager::get_stdout_models_map())
            std::cout << name_and_constructor.first << std::endl;
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
    std::string client_name = "client";
    if (!get_program_options()->value("path_to_client").empty()) {
        std::filesystem::path client_path(get_program_options()->value("path_to_client"));
        client_name = client_path.stem().string();
    }

    fuzzing::termination_info const  terminator{
            .max_driver_executions = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_executions"))),
            .max_fuzzing_seconds = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_seconds")))
            };

    iomodels::iomanager::instance().set_config({
            .max_trace_length = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_trace_length"))),
            .max_stack_size = (natural_8_bit)std::max(0, std::stoi(get_program_options()->value("max_stack_size"))),
            .max_stdin_bits = (iomodels::stdin_base::bit_count_type)std::max(0, std::stoi(get_program_options()->value("max_stdin_bits"))),
            .stdin_model_name = get_program_options()->value("stdin_model"),
            .stdout_model_name = get_program_options()->value("stdout_model")
            });

    fuzzing::print_fuzzing_configuration(
            std::cout,
            client_name,
            iomodels::iomanager::instance().get_config(),
            terminator
            );

    connection::server server(get_program_options()->value_as_int("port"), get_program_options()->value("path_to_client"));
    try {
        server.start();
    }
    catch (std::exception& e) {
        std::cerr << "ERROR: starting server\n" << e.what() << "\n";
        return;
    }

    std::cout << "Fuzzing started..." << std::endl << std::flush;

    fuzzing::analysis_outcomes const  results = fuzzing::run(
            [&server](){ server.send_input_to_client_and_receive_result(); },
            terminator,
            get_program_options()->has("debug_mode")
            );

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

            if (test_type == "debug") {
                fuzzing::save_execution_records_to_directory(
                    output_dir,
                    results.execution_records,
                    true,
                    test_name
                    );
                if (!results.debug_data.empty())
                {
                    std::cout << "Saving debug data under the output directory...";
                    fuzzing::save_debug_data_to_directory(
                            output_dir,
                            test_name,
                            results.debug_data
                            );
                }
            }
            else if (test_type == "testcomp") {
                fuzzing::save_testcomp_output(
                    output_dir, 
                    results.execution_records,
                    test_name,
                    get_program_version(),
                    get_program_options()->value("path_to_client")
                    );
            }
            
            std::cout << "Done.\n" << std::flush;
        }
    }
}
