#ifndef CONNECTION_CLIENT_HPP_INCLUDED
#   define CONNECTION_CLIENT_HPP_INCLUDED

#   include <boost/asio.hpp>

#   include <connection/message.hpp>
#   include <connection/connection.hpp>
#   include <connection/shared_memory.hpp>
#   include <connection/target_executor.hpp>

namespace  connection {


struct  client
{
    client(boost::asio::io_context& io_context, target_executor executor);
    
    void run(const std::string& address, const std::string& port);
    void connect(const std::string& address, const std::string& port);
    void receive_input();
    void execute_program_and_send_results();

private:
    boost::asio::io_context& io_context;
    std::unique_ptr<connection> connection_to_server;
    target_executor executor;
};


}

#endif
