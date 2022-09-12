#ifndef CONNECTION_SERVER_HPP_INCLUDED
#   define CONNECTION_SERVER_HPP_INCLUDED

#   include <boost/asio.hpp>

#   include <connection/medium.hpp>
#   include <connection/session.hpp>
#   include <fuzzing/analysis_outcomes.hpp>
#   include <fuzzing/termination_info.hpp>
#   include <connection/ts_queue.hpp>

#   include <string>

namespace  connection {


struct  server
{
    server(uint16_t port);
    
    fuzzing::analysis_outcomes  run_fuzzing(std::string const&  fuzzer_name, fuzzing::termination_info const&  info);
    
    void  send_input_to_client_and_receive_result();
    void  accept_connection();
    bool  start();

private:
    medium buffer;
    boost::asio::io_context io_context;
    std::thread thread;
    boost::asio::ip::tcp::acceptor acceptor;
    ts_queue<std::shared_ptr<session>> sessions;
};


}

#endif
