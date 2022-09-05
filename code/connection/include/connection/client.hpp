#ifndef CONNECTION_CLIENT_HPP_INCLUDED
#   define CONNECTION_CLIENT_HPP_INCLUDED

#   include <boost/asio.hpp>

#   include <connection/medium.hpp>

namespace  connection {


struct  client
{
    client(boost::asio::io_context& io_context);
    void  execute_program_and_send_results();
    void execute_program_input_mode(const std::string& input);
    void connect(const std::string& address, const std::string& port);
    void receive_input();

private:
    boost::asio::io_context& io_context;
    boost::asio::ip::tcp::socket socket;
    medium buffer;
};


}

#endif
