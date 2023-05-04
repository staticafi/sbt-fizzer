#include <server/program_info.hpp>
#include <server/program_options.hpp>
#include <connection/server.hpp>
#include <iomodels/iomanager.hpp>
#include <fuzzing/analysis_outcomes.hpp>
#include <fuzzing/fuzzing_loop.hpp>
#include <fuzzing/optimization_outcomes.hpp>
#include <fuzzing/optimizer.hpp>
#include <fuzzing/progress_recorder.hpp>
#include <fuzzing/dump.hpp>
#include <fuzzing/dump_native.hpp>
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
    if (get_program_options()->value("path_to_client").empty())
    {
        std::cerr << "WARNING: empty path to client specified. The server will not automatically run fuzzing clients.\n";
    }
    std::string client_name = "client";
    {
        if (!std::filesystem::is_regular_file(get_program_options()->value("path_to_client")))
        {
            std::cerr << "ERROR: The passed client path '"
                      << get_program_options()->value("path_to_client")
                      << "' does not reference a regular file.\n";
            return;
        }
        std::filesystem::perms const perms = std::filesystem::status(get_program_options()->value("path_to_client")).permissions();
        if ((perms & std::filesystem::perms::owner_exec) == std::filesystem::perms::none)
        {
            std::cerr << "ERROR: The passed client path '"
                      << get_program_options()->value("path_to_client")
                      << "' references a file which is NOT executable.\n";
            return;
        }
        std::filesystem::path client_path(get_program_options()->value("path_to_client"));
        client_name = client_path.stem().string();
    }

    std::string test_name;
    if (!get_program_options()->value("path_to_client").empty()) {
        test_name = client_name + "_test";
    } else {
        test_name = "test";        
    }

    const std::string& test_type = get_program_options()->value("test_type");
    if (test_type != "native" && test_type != "testcomp") {
        std::cerr << "ERROR: unknown output type specified. Use native or testcomp.\n";
        return;
    }

    if (get_program_options()->value("output_dir").empty())
    {
        std::cerr << "ERROR: The output directory path is empty.\n";
        return;
    }
    std::filesystem::path output_dir = std::filesystem::absolute(get_program_options()->value("output_dir"));
    {
        std::error_code  ec;
        if (test_type == "testcomp") 
        {
            std::filesystem::create_directories(output_dir / "test-suite", ec);
        }
        else {
            std::filesystem::create_directories(output_dir, ec);
        }
        if (ec)
        {
            std::cerr << "ERROR: Failed to create/access the output directory:\n        " << output_dir << "\n";
            return;
        }
    }

    fuzzing::termination_info const  terminator{
            .max_executions = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_executions"))),
            .max_seconds = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_seconds")))
            };

    iomodels::iomanager::instance().set_config({
            .max_trace_length = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_trace_length"))),
            .max_stack_size = (natural_8_bit)std::max(0, std::stoi(get_program_options()->value("max_stack_size"))),
            .max_stdin_bytes = (iomodels::stdin_base::byte_count_type)std::max(0, std::stoi(get_program_options()->value("max_stdin_bytes"))),
            .max_exec_milliseconds = (natural_16_bit)std::max(0, std::stoi(get_program_options()->value("max_exec_milliseconds"))),
            .max_exec_megabytes = (natural_16_bit)std::max(0, std::stoi(get_program_options()->value("max_exec_megabytes"))),
            .stdin_model_name = get_program_options()->value("stdin_model"),
            .stdout_model_name = get_program_options()->value("stdout_model")
            });

    fuzzing::optimizer::configuration const  optimizer_config{
            .max_seconds = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("optimizer_max_seconds"))),
            .max_trace_length = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("optimizer_max_trace_length"))),
            .max_stdin_bytes = (iomodels::stdin_base::byte_count_type)std::max(0, std::stoi(get_program_options()->value("optimizer_max_stdin_bytes")))
            };

    fuzzing::recorder().start(output_dir);

    connection::server server(get_program_options()->value_as_int("port"), get_program_options()->value("path_to_client"));
    try {
        server.start();
    }
    catch (std::exception& e) {
        std::cerr << "ERROR: starting server\n" << e.what() << "\n";
        return;
    }

    if (!get_program_options()->has("silent_mode"))
    {
        std::cout << "Configuration for fuzzing:" << std::endl;
        fuzzing::print_fuzzing_configuration(
                std::cout,
                client_name,
                iomodels::iomanager::instance().get_config(),
                terminator
                );
    }
    fuzzing::log_fuzzing_configuration(
            client_name,
            iomodels::iomanager::instance().get_config(),
            terminator
            );
    fuzzing::save_fuzzing_configuration(
            output_dir, 
            client_name,
            iomodels::iomanager::instance().get_config(),
            terminator
            );

    if (!get_program_options()->has("silent_mode"))
        std::cout << "Fuzzing was started..." << std::endl << std::flush;

    fuzzing::analysis_outcomes const  results = fuzzing::run(
            [&server](){ server.send_input_to_client_and_receive_result(); },
            terminator,
            get_program_options()->has("debug_mode")
            );

    if (!get_program_options()->has("silent_mode"))
    {
        std::cout << "Fuzzing was stopped. Details:" << std::endl;
        fuzzing::print_analysis_outcomes(std::cout, results);

        std::cout << "Configuration for test suite optimization:" << std::endl;
        fuzzing::print_optimization_configuration(std::cout, optimizer_config);
    }
    fuzzing::log_optimization_configuration(optimizer_config);
    fuzzing::save_optimization_configuration(output_dir, client_name, optimizer_config);

    std::unique_ptr<fuzzing::optimization_outcomes>  opt_results_ptr;
    if (optimizer_config.max_seconds > 0)
    {
        if (!get_program_options()->has("silent_mode"))
            std::cout << "Optimization was started..." << std::endl << std::flush;

        opt_results_ptr = std::make_unique<fuzzing::optimization_outcomes>();
        fuzzing::optimizer  opt{
                optimizer_config,
                results,
                [&server](){ server.send_input_to_client_and_receive_result(); },
                *opt_results_ptr
                };
        opt.run();

        if (!get_program_options()->has("silent_mode"))
        {
            std::cout << "Optimization was stopped. Details:" << std::endl;
            fuzzing::print_optimization_outcomes(std::cout, *opt_results_ptr);
        }
    }

    server.stop();

    fuzzing::recorder().stop();

    fuzzing::log_analysis_outcomes(results);
    fuzzing::save_analysis_outcomes(output_dir, client_name, results);
    if (opt_results_ptr != nullptr)
    {
        fuzzing::log_optimization_outcomes(*opt_results_ptr);
        fuzzing::save_optimization_outcomes(output_dir, client_name, *opt_results_ptr);
    }

    std::vector<fuzzing::execution_record> const* const  test_suite_ptr =
        opt_results_ptr != nullptr ? &opt_results_ptr->execution_records : &results.execution_records;

    if (!get_program_options()->has("silent_mode"))
        std::cout << "Saving tests under the output directory...\n";
    if (test_type == "native") {
        fuzzing::save_native_output(output_dir, *test_suite_ptr, test_name);
        if (!results.debug_data.empty())
        {
            if (!get_program_options()->has("silent_mode"))
                std::cout << "Saving debug data under the output directory...\n";
            fuzzing::save_debug_data_to_directory(output_dir, test_name, results.debug_data);
        }
    }
    else {
        ASSUMPTION(test_type == "testcomp");
        fuzzing::save_testcomp_output(
            output_dir / "test-suite", 
            *test_suite_ptr,
            test_name,
            get_program_version(),
            get_program_options()->value("path_to_client")
            );
    }
    
    if (!get_program_options()->has("silent_mode"))
        std::cout << "Done.\n" << std::flush;
}
