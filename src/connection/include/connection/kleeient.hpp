#ifndef CONNECTION_KLEEIENT_HPP_INCLUDED
#   define CONNECTION_KLEEIENT_HPP_INCLUDED

#   include <boost/asio.hpp>
#   include <boost/process.hpp>
#   include <boost/property_tree/ptree.hpp>
#   include <connection/message.hpp>
#   include <connection/connection.hpp>
#   include <fstream>

namespace  connection {


struct kleeient
{
public:
    void run(const std::string& address, const std::string& port);
    static kleeient get_instance(boost::asio::io_context& io_context);

private:
    kleeient(
        boost::asio::io_context& io_context,
        std::unique_ptr<boost::process::child> klee_process,
        std::unique_ptr<std::ifstream> models,
        std::unique_ptr<std::ofstream> traces);

    bool connect(const std::string& address, const std::string& port);
    bool receive_input(std::vector<bool>& trace);
    std::string invoke_klee(const std::vector<bool> &trace);
    void write_stdin(message& ostr, std::vector<uint8_t>& bytes);
    void read_trace(message& istr, std::vector<bool>& trace);
    bool send_result(std::string);


    boost::asio::io_context& io_context;
    std::unique_ptr<connection> connection_to_server;
    std::unique_ptr<std::ifstream> models;
    std::unique_ptr<std::ofstream> traces;
    std::unique_ptr<boost::process::child> klee_process;
};


}

#endif
