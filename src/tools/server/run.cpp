#include <server/program_info.hpp>
#include <server/program_options.hpp>
#include <connection/benchmark_executor.hpp>
#include <iomodels/iomanager.hpp>
#include <iomodels/models_map.hpp>
#include <fuzzing/analysis_outcomes.hpp>
#include <fuzzing/fuzzing_loop.hpp>
#include <fuzzing/execution_record_writer.hpp>
#include <fuzzing/optimization_outcomes.hpp>
#include <fuzzing/optimizer.hpp>
#include <fuzzing/progress_recorder.hpp>
#include <fuzzing/dump.hpp>
#include <fuzzing/dump_native.hpp>
#include <fuzzing/dump_testcomp.hpp>
#include <iostream>
#include <fstream>


void run(int argc, char* argv[])
{
    std::chrono::system_clock::time_point const  start_time_point = std::chrono::system_clock::now();

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
    if (get_program_options()->has("clear_output_dir"))
    {
        for (const auto&  entry : std::filesystem::directory_iterator(output_dir))
            if (entry.is_regular_file())
            {
                auto const name{ entry.path().filename().string() };
                for (auto const& suffix : {
                        "_config.json", "_outcomes.json",
                        "_LOG.html", "_TMPROF.html",
                        "0.json", "1.json", "2.json", "3.json", "4.json", "5.json", "6.json", "7.json", "8.json", "9.json",
                         })
                    if (name.ends_with(suffix))
                        std::filesystem::remove(entry);
            }
        if (std::filesystem::is_directory(output_dir / "test-suite"))
            for (const auto&  entry : std::filesystem::directory_iterator(output_dir / "test-suite"))
                std::filesystem::remove(entry);
        if (std::filesystem::is_directory(output_dir / "progress_recording"))
            std::filesystem::remove_all(output_dir / "progress_recording");
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
    std::filesystem::perms const perms = std::filesystem::status(get_program_options()->value("path_to_target")).permissions();
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

    fuzzing::termination_info  terminator{
            .max_executions = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_executions"))),
            .max_seconds = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_seconds")))
            };

    iomodels::iomanager::instance().set_config({
            .max_exec_milliseconds = (natural_16_bit)std::max(0, std::stoi(get_program_options()->value("max_exec_milliseconds"))),
            .max_trace_length = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_trace_length"))),
            .max_br_instr_trace_length = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_br_instr_trace_length"))),
            .max_stack_size = (natural_8_bit)std::max(0, std::stoi(get_program_options()->value("max_stack_size"))),
            .max_stdin_bytes = (iomodels::stdin_base::byte_count_type)std::max(0, std::stoi(get_program_options()->value("max_stdin_bytes"))),
            .max_exec_megabytes = (natural_16_bit)std::max(0, std::stoi(get_program_options()->value("max_exec_megabytes"))),
            .stdin_model_name = get_program_options()->value("stdin_model"),
            .stdout_model_name = get_program_options()->value("stdout_model")
            });

    fuzzing::optimizer::configuration  optimizer_config{
            .max_seconds = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("optimizer_max_seconds"))),
            .max_trace_length = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("optimizer_max_trace_length"))),
            .max_stdin_bytes = (iomodels::stdin_base::byte_count_type)std::max(0, std::stoi(get_program_options()->value("optimizer_max_stdin_bytes")))
            };
    if (optimizer_config.max_seconds > 0U && optimizer_config.max_trace_length <= iomodels::iomanager::instance().get_config().max_trace_length)
    {
        std::cerr << "ERROR: The 'optimizer_max_trace_length' must be greater than 'max_trace_length'.\n";
        return;
    }
    if (optimizer_config.max_seconds > 0U && optimizer_config.max_stdin_bytes <= iomodels::iomanager::instance().get_config().max_stdin_bytes)
    {
        std::cerr << "ERROR: The 'optimizer_max_stdin_bytes' must be greater than 'max_stdin_bytes'.\n";
        return;
    }

    if (get_program_options()->has("progress_recording")) {
        fuzzing::recorder().start(std::filesystem::absolute(get_program_options()->value("path_to_target")), output_dir);
    }

    std::string  target_name = std::filesystem::path(get_program_options()->value("path_to_target")).filename().string();
    {
        std::string const  target_suffix = "_sbt-fizzer_target";
        std::string::size_type const  suffix_i = target_name.find(target_suffix);
        if (suffix_i != std::string::npos) {
            target_name.erase(suffix_i, target_suffix.length());
        }
    }

    std::shared_ptr<connection::benchmark_executor>  benchmark_executor;
    if (get_program_options()->has("path_to_client"))
    {
        if (!get_program_options()->has("silent_mode"))
            std::cout << "\"communication_type\": \"network\"," << std::endl;

        benchmark_executor = std::make_shared<connection::benchmark_executor_via_network>(
                get_program_options()->value("path_to_client"),
                get_program_options()->value("path_to_target"),
                get_program_options()->value_as_int("port")
                );
    }
    else
    {
        if (!get_program_options()->has("silent_mode"))
            std::cout << "\"communication_type\": \"shared_memory\"," << std::endl;

        benchmark_executor = std::make_shared<connection::benchmark_executor_via_shared_memory>(
                get_program_options()->value("path_to_target")
                );
    }

    auto const startup_time = std::chrono::duration<float_64_bit>(std::chrono::system_clock::now() - start_time_point).count();

    {
        float_64_bit const  total_time{ std::max((float_64_bit)(terminator.max_seconds + optimizer_config.max_seconds), 1.0) };
        float_64_bit const  remaining_time{ std::max(total_time - startup_time, 0.0) };
        terminator.max_seconds = (natural_32_bit)(remaining_time * (terminator.max_seconds / total_time));
        optimizer_config.max_seconds = (natural_32_bit)(remaining_time * (optimizer_config.max_seconds / total_time));

        if (!get_program_options()->has("silent_mode"))
            std::cout << "\"fuzzing_startup\": {" << std::endl
                      << "    \"time\": " << startup_time << ',' << std::endl
                      << "    \"--max_seconds\": " << terminator.max_seconds << ',' << std::endl
                      << "    \"--optimizer_max_seconds\": " << optimizer_config.max_seconds << std::endl
                      << "}," << std::endl;
    }

    fuzzing::execution_record_writer  execution_record_writer{
            output_dir,
            target_name,
            get_program_version(),
            test_type == "native"
            };

    if (!get_program_options()->has("silent_mode"))
    {
        std::cout << "\"fuzzing_configuration\": ";
        fuzzing::print_fuzzing_configuration(
                std::cout,
                target_name,
                iomodels::iomanager::instance().get_config(),
                terminator
                );
        std::cout << ',' << std::endl;
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

    std::vector<vecu8>  inputs_leading_to_boundary_violation;
    fuzzing::analysis_outcomes const results = fuzzing::run(
        *benchmark_executor,
        execution_record_writer,
        [&inputs_leading_to_boundary_violation, &optimizer_config](fuzzing::execution_record const&  record) {
                if (optimizer_config.max_seconds > 0)
                    inputs_leading_to_boundary_violation.push_back(record.stdin_bytes);
                },
        terminator
        );

    if (!get_program_options()->has("silent_mode"))
    {
        std::cout << "\"fuzzing_results\": ";
        fuzzing::print_analysis_outcomes(std::cout, results);
    }
    fuzzing::log_analysis_outcomes(results);
    fuzzing::save_analysis_outcomes(output_dir, target_name, results);

    fuzzing::recorder().stop();

    if (!inputs_leading_to_boundary_violation.empty() && optimizer_config.max_seconds > 0)
    {
        if (!get_program_options()->has("silent_mode"))
        {
            std::cout << ',' << std::endl
                      << "\"optimization_configuration\": ";
            fuzzing::print_optimization_configuration(std::cout, optimizer_config);
            std::cout << ',' << std::endl;
        }
        fuzzing::log_optimization_configuration(optimizer_config);
        fuzzing::save_optimization_configuration(output_dir, target_name, optimizer_config);

        fuzzing::optimizer  opt{ optimizer_config };

        {
            iomodels::configuration  io_cfg = iomodels::iomanager::instance().get_config();
            io_cfg.max_trace_length = optimizer_config.max_trace_length;
            io_cfg.max_stdin_bytes = optimizer_config.max_stdin_bytes;
            iomodels::iomanager::instance().set_config(io_cfg);
            benchmark_executor->on_io_config_changed();
        }

        fuzzing::optimization_outcomes const  opt_results = opt.run(
                inputs_leading_to_boundary_violation,
                results.covered_branchings,
                results.uncovered_branchings,
                *benchmark_executor,
                execution_record_writer
                );

        if (!get_program_options()->has("silent_mode"))
        {
            std::cout << "\"optimization_results\": ";
            fuzzing::print_optimization_outcomes(std::cout, opt_results);
        }
        fuzzing::log_optimization_outcomes(opt_results);
        fuzzing::save_optimization_outcomes(output_dir, target_name, opt_results);
    }
}
