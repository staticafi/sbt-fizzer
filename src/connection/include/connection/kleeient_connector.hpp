#ifndef CONNECTION_KLEEIENT_CONNECTOR_HPP_INCLUDED
#   define CONNECTION_KLEEIENT_CONNECTOR_HPP_INCLUDED

#   include <boost/asio.hpp>
#   include <connection/connection.hpp>


namespace  connection {


struct  kleeient_connector
{
    kleeient_connector(uint16_t port);
    void  wait_for_connection();
    bool  get_model(const std::vector<bool> trace, std::vector<uint8_t>& model);
    
private:
    void send_trace(const std::vector<bool>& trace);
    bool receive_response(std::vector<uint8_t>& model);

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor acceptor;
    std::shared_ptr<connection> kleeient_connection;
};


}

#endif
