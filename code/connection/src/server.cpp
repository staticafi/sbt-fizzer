#include <connection/server.hpp>
#include <connection/client.hpp>
#include <iomodels/iomanager.hpp>
#include <fuzzing/fuzzing_loop.hpp>
#include <fuzzing/fuzzers_map.hpp>
#include <utility/assumptions.hpp>

#include <sstream>

namespace  connection {


server::server( uint16_t port):
    acceptor(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port))
    {}

void server::wait_for_result() {
    in_buffer.wait();
}


void server::clear_input_buffer() {
    in_buffer.clear();
}


bool server::start() {
    try {
        wait_for_connection();
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
    return fuzzing::run(*this, fuzzing::get_fuzzers_map().at(fuzzer_name)(info));
}


void server::wait_for_connection() {
    acceptor.async_accept(
        [this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
            if (ec) {
                std::cout << "ERROR: new connection" << std::endl;
                std::cout << ec.what() << std::endl;
                return;
            }
            
            std::shared_ptr<session> new_session = std::make_shared<session>(io_context, std::move(socket), in_buffer, out_buffer);
            std::cout << "Accepted connection from client, sending input..." << std::endl;
            sessions.push_back(std::move(new_session));
            sessions.back()->send_input_to_client();
            wait_for_connection();
            
        }
    );
}

void  server::load_result_from_client()
{
    iomodels::iomanager::instance().load_trace(in_buffer);
    iomodels::iomanager::instance().load_stdin(in_buffer);
    iomodels::iomanager::instance().load_stdout(in_buffer);
}


}
