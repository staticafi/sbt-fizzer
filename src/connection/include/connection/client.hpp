#ifndef CONNECTION_CLIENT_HPP_INCLUDED
#   define CONNECTION_CLIENT_HPP_INCLUDED

#   include <boost/asio.hpp>

#   include <connection/message.hpp>
#   include <connection/connection.hpp>

namespace  connection {


struct  client
{
    client(boost::asio::io_context& io_context);
    void execute_program();
    void run_input_mode(vecu8 input_bytes);
    void run(const std::string& address, const std::string& port);
    bool connect(const std::string& address, const std::string& port);
    bool receive_input();
    bool execute_program_and_send_results();

private:
    boost::asio::io_context& io_context;
    std::unique_ptr<connection> connection_to_server;
};


}

#endif
