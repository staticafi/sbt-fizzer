#ifndef CONNECTION_SERVER_HPP_INCLUDED
#   define CONNECTION_SERVER_HPP_INCLUDED

#   include <boost/asio.hpp>

#   include <connection/message.hpp>
#   include <connection/connection.hpp>
#   include <connection/client_configuration.hpp>
#   include <connection/ts_queue.hpp>

#   include <string>

namespace  connection {

struct  server
{
    server(uint16_t port);
    
    void  start();
    void  stop();

    void  send_input_to_client(connection& connection, const client_configuration& config);
    void  receive_result_from_client(connection& connection);
    void  send_input_to_client_and_receive_result(const client_configuration& config);
    
private:
    void  accept_connections();

    boost::asio::io_context io_context;
    std::thread io_context_thread;
    boost::asio::ip::tcp::acceptor acceptor;
    ts_queue<connection> connections;
    std::exception_ptr client_executor_excptr;


friend struct client_executor;
};


}

#endif
