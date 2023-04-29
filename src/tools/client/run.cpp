#include <boost/asio.hpp>
#include <boost/algorithm/hex.hpp>

#include <client/program_options.hpp>
#include <connection/client.hpp>
#include <connection/target_executor.hpp>
#include <iomodels/iomanager.hpp>

#include <iostream>

void run() {
    if (!get_program_options()->has("path_to_target")) {
        std::cerr << "ERROR: no path to target specified.\n";
        return;
    }
    boost::asio::io_context io_context;
    connection::target_executor executor(get_program_options()->value("path_to_target"));
    connection::client client(io_context, std::move(executor));
    if (!get_program_options()->has("input")) {
        client.run(get_program_options()->value("address"), get_program_options()->value("port"));
        return;
    }

    iomodels::iomanager& iomanager = iomodels::iomanager::instance();

    iomanager.set_config({
        .max_trace_length = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_trace_length"))),
        .max_br_instr_trace_length = (natural_32_bit)std::max(0, std::stoi(get_program_options()->value("max_br_instr_trace_length"))),
        .max_stack_size = (natural_8_bit)std::max(0, std::stoi(get_program_options()->value("max_stack_size"))),
        .max_stdin_bytes = (iomodels::stdin_base::byte_count_type)std::max(0, std::stoi(get_program_options()->value("max_stdin_bytes"))),
        .max_exec_megabytes = (natural_16_bit)std::max(0, std::stoi(get_program_options()->value("max_exec_megabytes"))),
        .stdin_model_name = get_program_options()->value("stdin_model"),
        .stdout_model_name = get_program_options()->value("stdout_model")
    });

    client.executor.timeout_ms = (natural_16_bit)std::max(0, std::stoi(get_program_options()->value("max_exec_milliseconds")));

    vecu8 input_bytes;
    try {
        boost::algorithm::unhex(get_program_options()->value("input"), std::back_inserter(input_bytes));
    } 
    catch (boost::algorithm::hex_decode_error &) {
        std::cerr << "ERROR: in argument input expected hexadecimal value\n";
        return;
    }
    if (input_bytes.size() > iomanager.get_stdin()->max_bytes()) {
        std::cerr << "ERROR: the count of bits in the passed input (" << 8ULL * input_bytes.size()
                    << ") is above the limit (" << iomanager.get_stdin()->max_bytes() << ").\n";
        return;
    }
    client.run_input_mode(std::move(input_bytes));
}