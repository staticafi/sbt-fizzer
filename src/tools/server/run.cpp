#include <server/program_info.hpp>
#include <server/program_options.hpp>
#include <connection/client_executor.hpp>
#include <connection/target_executor.hpp>
#include <connection/server.hpp>
#include <connection/client_configuration.hpp>
#include <iomodels/iomanager.hpp>
#include <iomodels/models_map.hpp>
#include <fuzzing/analysis_outcomes.hpp>
#include <fuzzing/fuzzing_loop.hpp>
#include <fuzzing/dump.hpp>
#include <fuzzing/dump_native.hpp>
#include <fuzzing/dump_testcomp.hpp>
#include <iostream>


void run(int argc, char* argv[])
{
    if (get_program_options()->has("list_stdin_models"))
    {
        for (auto const&  name_and_constructor : iomodels::get_stdin_models_map())
            std::cout << name_and_constructor.first << std::endl;
        return;
    }
    if (get_program_options()->has("list_stdout_models"))
    {
        for (auto const&  name_and_constructor : iomodels::get_stdout_models_map())
            std::cout << name_and_constructor.first << std::endl;
        return;
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
    if (!get_program_options()->has("path_to_target")) {
        std::cerr << "ERROR: The path to target is empty.\n";
        return;
    }
    if (!std::filesystem::is_regular_file(get_program_options()->value("path_to_target")))
    {
        std::cerr << "ERROR: The passed target path '"
                    << get_program_options()->value("path_to_target")
                    << "' does not reference a regular file.\n";
        return;
    }
    std::filesystem::perms const perms = std::filesystem::status(get_program_options()->value("path_to_client")).permissions();
    if ((perms & std::filesystem::perms::owner_exec) == std::filesystem::perms::none)
    {
        std::cerr << "ERROR: The passed target path '"
                    << get_program_options()->value("path_to_target")
                    << "' references a file which is NOT executable.\n";
        return;
    }
    if (get_program_options()->has("path_to_client")) {
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
    }

    fuzzing::termination_info const  terminator{
            .max_driver_executions = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_executions"))),
            .max_fuzzing_seconds = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_seconds")))
            };

    iomodels::iomanager::instance().set_config({
            .max_trace_length = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_trace_length"))),
            .max_br_instr_trace_length = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_br_instr_trace_length"))),
            .max_stack_size = (natural_8_bit)std::max(0, std::stoi(get_program_options()->value("max_stack_size"))),
            .max_stdin_bytes = (iomodels::stdin_base::byte_count_type)std::max(0, std::stoi(get_program_options()->value("max_stdin_bytes"))),
            .stdin_model_name = get_program_options()->value("stdin_model"),
            .stdout_model_name = get_program_options()->value("stdout_model")
            });

    const natural_32_bit timeout_ms = std::max(0, std::stoi(get_program_options()->value("timeout")));
    std::string target_name = std::filesystem::path(get_program_options()->value("path_to_target")).stem().string();
    {
        std::string target_suffix = "_sbt-fizzer_target";
        std::string::size_type suffix_i = target_name.find(target_suffix);
        if (suffix_i != std::string::npos) {
            target_name.erase(suffix_i, target_suffix.length());
        }
    }

    if (!get_program_options()->has("silent_mode"))
    {
        std::cout << "Accepted the following configuration:" << std::endl;
        fuzzing::print_fuzzing_configuration(
                std::cout,
                target_name,
                iomodels::iomanager::instance().get_config(),
                terminator
                );
    }
    fuzzing::log_fuzzing_configuration(
            target_name,
            iomodels::iomanager::instance().get_config(),
            terminator
            );
    fuzzing::save_fuzzing_configuration(
            output_dir, 
            target_name,
            iomodels::iomanager::instance().get_config(),
            terminator
            );

    connection::server server(get_program_options()->value_as_int("port"));
    server.start();

    if (!get_program_options()->has("silent_mode"))
        std::cout << "Fuzzing was started..." << std::endl;

    fuzzing::analysis_outcomes results;
    if (get_program_options()->has("path_to_client")) {
        std::string client_invocation = get_program_options()->value("path_to_client") +
            " --path_to_target " + get_program_options()->value("path_to_target") +
            " --port " + get_program_options()->value("port");

        connection::client_configuration client_config{
            (natural_32_bit) iomodels::iomanager::instance().get_config().required_shared_memory_size(),
            timeout_ms
        };

        auto run_client = [&server, &client_config](){ 
            server.send_input_to_client_and_receive_result(client_config); 
        };

        connection::client_executor executor(5, std::move(client_invocation), server);
        executor.start();
        results = fuzzing::run(
            run_client,
            terminator,
            get_program_options()->has("debug_mode")
            );
        executor.stop();
    }
    else {
        connection::shared_memory_remover remover;
        connection::target_executor executor(get_program_options()->value("path_to_target"));
        executor.timeout_ms = timeout_ms;
        executor.init_shared_memory(iomodels::iomanager::instance().get_config().required_shared_memory_size());

        auto run_target = [&executor] {
            executor.shared_memory.clear();
            iomodels::iomanager::instance().get_config().save(executor.shared_memory);
            iomodels::iomanager::instance().get_stdin()->save(executor.shared_memory);
            iomodels::iomanager::instance().get_stdout()->save(executor.shared_memory);
            executor.execute_target();
            iomodels::iomanager::instance().clear_trace();
            iomodels::iomanager::instance().clear_br_instr_trace();
            iomodels::iomanager::instance().get_stdin()->clear();
            iomodels::iomanager::instance().get_stdout()->clear();
            iomodels::iomanager::instance().load_results(executor.shared_memory);
        };

        results = fuzzing::run(
            run_target,
            terminator,
            get_program_options()->has("debug_mode")
            );
    }

    server.stop();

    if (!get_program_options()->has("silent_mode"))
    {
        std::cout << "Fuzzing was stopped. Details:" << std::endl;
        fuzzing::print_analysis_outcomes(std::cout, results);
    }
    fuzzing::log_analysis_outcomes(results);
    fuzzing::save_analysis_outcomes(output_dir, target_name, results);

    std::string test_name = target_name + "_test";

    if (!get_program_options()->has("silent_mode"))
        std::cout << "Saving tests under the output directory...\n";
    
    if (test_type == "native") {
        fuzzing::save_native_output(output_dir, results.execution_records, test_name);
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
            results.execution_records,
            test_name,
            get_program_version(),
            get_program_options()->value("path_to_client")
            );
    }
    
    if (!get_program_options()->has("silent_mode"))
        std::cout << "Done." << std::endl;
}
