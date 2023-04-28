#ifndef CONNECTION_SERVER_HPP_INCLUDED
#   define CONNECTION_SERVER_HPP_INCLUDED

#   include <boost/asio.hpp>

#   include <connection/message.hpp>
#   include <connection/connection.hpp>
#   include <fuzzing/analysis_outcomes.hpp>
#   include <fuzzing/termination_info.hpp>
#   include <connection/ts_queue.hpp>
#   include <connection/client_executor.hpp>
#   include <iomodels/iomanager.hpp>

#   include <string>
#   include <atomic>
#   include <mutex>
#   include <condition_variable>
#   include <memory>

namespace  connection {


struct client_crash_exception: public std::runtime_error{
    explicit client_crash_exception(std::string const& msg) : std::runtime_error(msg) {}
};


struct  server
{
    server(uint16_t port, std::string path_to_client);
    
    void  start();
    void  stop();

    void  send_input_to_client_and_receive_result();
    
private:
    void  accept_connection();
    void  send_input_to_client_and_receive_result(std::shared_ptr<connection> connection);

    boost::asio::io_context io_context;
    std::string client_path_and_port;
    iomodels::iomanager::configuration  iom_config;
    std::thread thread;
    boost::asio::ip::tcp::acceptor acceptor;
    ts_queue<std::shared_ptr<connection>> connections;
    std::unique_ptr<client_executor> client_executor_;
};


}

#endif
