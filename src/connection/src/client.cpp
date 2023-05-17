#include <connection/client.hpp>
#include <connection/message.hpp>
#include <connection/connection.hpp>
#include <iomodels/ioexceptions.hpp>
#include <iomodels/stdin_base.hpp>
#include <iomodels/iomanager.hpp>

#include <iostream>

namespace  connection {


client::client(boost::asio::io_context& io_context, target_executor executor):
    io_context(io_context),
    executor(std::move(executor))
    {}


void client::run_input_mode(vecu8 input_bytes) {
    iomodels::iomanager& iomanager = iomodels::iomanager::instance();
    
    executor.init_shared_memory(iomanager.get_config().required_shared_memory_size());
    iomanager.get_config().save_target_config(executor.shared_memory);

    executor.shared_memory << (iomodels::stdin_base::byte_count_type) input_bytes.size();
    for (natural_8_bit byte: input_bytes) {
        executor.shared_memory << byte;
    }
    executor.shared_memory << (iomodels::stdin_base::byte_count_type) 0;
    
    executor.execute_target();

    iomodels::iomanager::instance().load_results(executor.shared_memory);

    std::cout << "trace length: " << iomanager.get_trace().size() << '\n';
    std::cout << "stdin_bytes: " << iomanager.get_stdin()->get_bytes().size() << '\n';
    for (const instrumentation::branching_coverage_info& info: iomanager.get_trace()) {
        std::cout << "location: bb" << info.id
                  << " branch: " << std::boolalpha << info.direction
                  << " value: " << info.value
                  << "\n";
    }
}


void client::run(const std::string& address, const std::string& port) {
    connect(address, port);

    try {
        receive_input();
        execute_program_and_send_results();
    }
    catch (boost::system::system_error const& e) {
        if (e.code() == boost::asio::error::eof) {
            return;
        }
        throw e;
    }
}

void client::connect(const std::string& address, const std::string& port) {
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(address, port);

    boost::asio::ip::tcp::socket socket(io_context);
    boost::asio::connect(socket, endpoints);
    connection_to_server = std::make_unique<connection>(std::move(socket));
}

void client::receive_input() {

    message input;
    connection_to_server->receive_message(input);
    natural_32_bit shared_memory_size;
    input >> shared_memory_size;
    natural_16_bit max_exec_milliseconds;
    input >> max_exec_milliseconds;

    executor.timeout_ms = max_exec_milliseconds;
    executor.init_shared_memory(shared_memory_size);

    executor.shared_memory.load(input);
}


void client::execute_program_and_send_results() {
    executor.execute_target();

    message results;
    executor.shared_memory.save(results);
    /* Clean up the shared memory segment. Does not really make sense when 
    fuzzing on the same computer, but that is what the direct mode is for. */
    executor.shared_memory.remove();
    connection_to_server->send_message(results);
}


}
