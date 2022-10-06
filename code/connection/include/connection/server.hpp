#ifndef CONNECTION_SERVER_HPP_INCLUDED
#   define CONNECTION_SERVER_HPP_INCLUDED

#   include <boost/asio.hpp>

#   include <connection/message.hpp>
#   include <connection/connection.hpp>
#   include <fuzzing/analysis_outcomes.hpp>
#   include <fuzzing/fuzzer_base.hpp>
#   include <fuzzing/termination_info.hpp>
#   include <connection/ts_queue.hpp>
#   include <connection/client_executor.hpp>

#   include <string>
#   include <atomic>
#   include <mutex>
#   include <condition_variable>

namespace  connection {


struct  server
{
    server(uint16_t port, std::string path_to_client);
    
    void  start();
    void  stop();
    void  accept_connection();
    void  send_input_to_client_and_receive_result(std::shared_ptr<connection> connection);

    void  fuzzing_loop(std::shared_ptr<fuzzing::fuzzer_base> const  fuzzer);
    fuzzing::analysis_outcomes  run_fuzzing(std::string const&  fuzzer_name, fuzzing::termination_info const&  info);
    

private:
    boost::asio::io_context io_context;
    std::thread thread;
    boost::asio::ip::tcp::acceptor acceptor;
    ts_queue<std::shared_ptr<connection>> connections;
    client_executor client_executor;
};


}

#endif
