#ifndef CONNECTION_SERVER_HPP_INCLUDED
#   define CONNECTION_SERVER_HPP_INCLUDED

#   include <boost/asio.hpp>

#   include <connection/medium.hpp>
#   include <connection/session.hpp>
#   include <fuzzing/analysis_outcomes.hpp>
#   include <fuzzing/termination_info.hpp>

#   include <string>

namespace  connection {


struct  server
{
    server(uint16_t port);
    void  load_result_from_client();

    fuzzing::analysis_outcomes  run_fuzzing(std::string const&  fuzzer_name, fuzzing::termination_info const&  info);

    void  wait_for_result();
    void  wait_for_connection();
    bool  start();
    void  clear_input_buffer();

private:
    medium in_buffer;
    medium out_buffer;
    boost::asio::io_context io_context;
    std::thread thread;
    boost::asio::ip::tcp::acceptor acceptor;
    std::deque<std::shared_ptr<session>> sessions;

};


}

#endif
