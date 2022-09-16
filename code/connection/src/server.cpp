#include <connection/server.hpp>
#include <connection/client.hpp>
#include <iomodels/iomanager.hpp>
#include <fuzzing/fuzzing_loop.hpp>
#include <fuzzing/fuzzers_map.hpp>
#include <utility/assumptions.hpp>

#include <sstream>

namespace  connection {


server::server(uint16_t port, std::string path_to_client):
    acceptor(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
    client_executor(10, std::move(path_to_client), sessions)
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


bool server::start() {
    try {
        accept_connection();
        thread = std::thread([this]() {io_context.run();});
    }
    catch (std::exception& e) {
        std::cout << "ERROR: " << e.what() << std::endl;
        return false;
    }
    return true;
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
            if (ec) {
                std::cout << "ERROR: new connection" << std::endl;
                std::cout << ec.what() << std::endl;
                return;
            }
            
            std::shared_ptr<session> new_session = std::make_shared<session>(io_context, std::move(socket), buffer);
            std::cout << "Accepted connection from client" << std::endl;
            sessions.push(std::move(new_session));
            accept_connection();
            
        }
    );
}

void  server::send_input_to_client_and_receive_result()
{
    buffer.clear();
    iomodels::iomanager::instance().save_stdin(buffer);
    iomodels::iomanager::instance().save_stdout(buffer);
    std::shared_ptr<session> session = sessions.wait_and_pop();
    std::future<std::size_t> send_input_future = session->send_input_to_client(boost::asio::use_future);
    size_t sent = send_input_future.get();
    std::cout << "Sent " << sent << " bytes to client" << std::endl;
    buffer.clear();

    std::future<std::size_t> receive_result_future = session->receive_input_from_client(boost::asio::use_future);
    size_t received = receive_result_future.get();
    std::cout << "Received " << received << " bytes from client" << std::endl;
    iomodels::iomanager::instance().clear_trace();
    iomodels::iomanager::instance().load_trace(buffer);
    iomodels::iomanager::instance().clear_stdin();
    iomodels::iomanager::instance().load_stdin(buffer);
    iomodels::iomanager::instance().clear_stdout();
    iomodels::iomanager::instance().load_stdout(buffer);
}


}
