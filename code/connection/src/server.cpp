#include <connection/server.hpp>
#include <connection/client.hpp>
#include <iomodels/iomanager.hpp>
#include <fuzzing/fuzzing_run.hpp>
#include <fuzzing/fuzzers_map.hpp>
#include <utility/timeprof.hpp>

#include <sstream>
#include <chrono>

namespace  connection {


server::server(uint16_t port, std::string path_to_client):
    acceptor(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
    client_executor(10, std::move(path_to_client), connections)
    {}


server::~server() {
    stop();
}


void server::stop() {
    io_context.stop();
    if (thread.joinable()) {
        thread.join();
    }
}


void server::start() {
    accept_connection();
    thread = std::thread([this]() {io_context.run();});
}


void  server::fuzzing_loop(std::shared_ptr<fuzzing::fuzzer_base> const  fuzzer)
{
    using namespace std::chrono_literals;
    while (true)
    {
        TMPROF_BLOCK();
        if (auto excptr = client_executor.get_exception_ptr()) {
            std::rethrow_exception(excptr);
        }
        if (auto connection = connections.wait_and_pop_or_timeout(2000ms)) {
            fuzzer->_on_driver_begin();
            send_input_to_client_and_receive_result(*connection);
            fuzzer->_on_driver_end();
        }
    }
}


fuzzing::analysis_outcomes  server::run_fuzzing(std::string const&  fuzzer_name, fuzzing::termination_info const&  info)
{
    ASSUMPTION(fuzzing::get_fuzzers_map().count(fuzzer_name) != 0UL);
    client_executor.start();
    fuzzing::analysis_outcomes results = fuzzing::run(*this, fuzzing::get_fuzzers_map().at(fuzzer_name)(info));
    client_executor.stop();
    return results;
}


void server::accept_connection() {
    acceptor.async_accept(
        [this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
            if (!ec) {
                auto new_connection = std::make_shared<connection>(io_context, std::move(socket), buffer);
                connections.push(std::move(new_connection));
            }
            else {
                std::cout << "ERROR: accepting connection" << std::endl;
                std::cout << ec.what() << std::endl;
            }
            accept_connection();
        }
    );
}

void  server::send_input_to_client_and_receive_result(std::shared_ptr<connection> connection)
{
    buffer.clear();
    iomodels::iomanager::instance().save_stdin(buffer);
    iomodels::iomanager::instance().save_stdout(buffer);
    std::future<std::size_t> send_input_future = connection->send_input_to_client(boost::asio::use_future);
    size_t sent = send_input_future.get();
    buffer.clear();

    std::future<std::size_t> receive_result_future = connection->receive_input_from_client(boost::asio::use_future);
    size_t received = receive_result_future.get();
    iomodels::iomanager::instance().clear_trace();
    iomodels::iomanager::instance().load_trace(buffer);
    iomodels::iomanager::instance().clear_stdin();
    iomodels::iomanager::instance().load_stdin(buffer);
    iomodels::iomanager::instance().clear_stdout();
    iomodels::iomanager::instance().load_stdout(buffer);
}


}
