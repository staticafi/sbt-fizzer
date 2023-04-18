#include <boost/process.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include <boost/filesystem.hpp>
#include <boost/dll.hpp>

#include <connection/kleeient.hpp>
#include <connection/message.hpp>
#include <connection/connection.hpp>

#include <iostream>
#include <fstream>

namespace connection {

kleeient::kleeient(
        boost::asio::io_context& io_context,
        std::unique_ptr<boost::process::child> klee_process,
        std::unique_ptr<std::ifstream> models,
        std::unique_ptr<std::ofstream> traces):
    io_context(io_context),
    klee_process(std::move(klee_process)),
    models(std::move(models)),
    traces(std::move(traces)) {}

kleeient kleeient::get_instance(boost::asio::io_context& io_context, const std::string& program_path)
{
    auto installation_dir = boost::dll::program_location().parent_path();
    auto klee_executable_path = installation_dir/"JetKlee/build/bin/klee";
    auto klee_libs_path = installation_dir/"JetKlee/build/Release+Asserts/lib";
    auto traces = std::string("traces");
    auto models = std::string("models");

    auto output_dir = installation_dir/"klee-output/";
    auto traces_path = output_dir/traces;
    auto models_path = output_dir/models;

    if (boost::filesystem::exists(output_dir))
        boost::filesystem::remove_all(output_dir);
    boost::filesystem::create_directory(output_dir);

    if (mkfifo(traces_path.c_str(), S_IRUSR | S_IWUSR) == -1) {
        throw std::runtime_error("Could not create traces pipe");
    }
    if (mkfifo(models_path.c_str(), S_IRUSR | S_IWUSR) == -1) {
        throw std::runtime_error("Could not create models pipe");
    }

    auto env = boost::this_process::environment();
    env["KLEE_RUNTIME_LIBRARY_PATH"] = klee_libs_path.string();
    std::unique_ptr<boost::process::child> process = std::make_unique<boost::process::child>(
        klee_executable_path,
        env,
        boost::process::args({
            "--output-dir", output_dir.string(),
            "--use-interactive-search",
            "--interactive-search-file", traces_path.string(),
            "--write-ktests=false",
            "--dump-states-on-halt=false",
            "--write-json",
            "--json-path", models, // relative to `output_dir`
            "--suppress-intermediate-queries",
            "--keep-finalized-states",
            program_path }));
    std::unique_ptr<std::ifstream> models_stream = std::make_unique<std::ifstream>(models_path);
    std::unique_ptr<std::ofstream> traces_stream = std::make_unique<std::ofstream>(traces_path);
    return kleeient(io_context, std::move(process), std::move(models_stream), std::move(traces_stream));
    // TODO: delete pipes in destructor (or maybe RAII solution?)
}

void kleeient::run(const std::string& address, const std::string& port) {
    if (!connect(address, port)) {
        return;
    }

    std::vector<bool> trace;
    while (true) {
        trace.clear();
        if (!receive_input(trace))
            return;
        auto klee_response = invoke_klee(trace);
        send_result(klee_response);
    }
}

bool kleeient::connect(const std::string& address, const std::string& port) {
    std::cout << "Connecting to " << address << ":" << port << std::endl;
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::system::error_code ec;
    boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(address, port, ec);
    if (ec) {
        std::cerr << "ERROR: could not resolve address and port\n" << ec.message() << "\n";
        return false;
    }

    boost::asio::ip::tcp::socket socket(io_context);
    boost::asio::connect(socket, endpoints, ec);
    if (ec) {
        std::cerr << "ERROR: could not connect to server\n" << ec.message() << "\n";
        return false;
    }
    connection_to_server = std::make_unique<connection>(std::move(socket));

    std::cout << "Connected to server" << std::endl;
    return true;
}

bool kleeient::receive_input(std::vector<bool>& trace) {
    boost::system::error_code ec;
    message input;
    connection_to_server->receive_message(input, ec);
    if (ec == boost::asio::error::eof) {
        return false;
    }
    else if (ec) {
        std::cerr << "ERROR: receiving input from server\n" << ec.message() << "\n";
        return false;
    }

    read_trace(input, trace);
    return true;
}

// input trace is obtained from iomanager
std::string kleeient::invoke_klee(const std::vector<bool>& trace)
{
    std::cout << "Received following trace:" << std::endl;
    for (bool dir : trace)
    {
        std::cout << dir;
        *traces << (dir ? "1" : "0");
    }
    *traces << std::endl << std::flush;

    std::cout << std::endl;

    std::cout << "Klee responded with following JSON:" << std::endl;
    std::string json_string;
    std::getline(*models, json_string);
    std::cout << json_string << std::endl;

    return json_string;
}

void kleeient::write_stdin(message& ostr, std::vector<uint8_t>& bytes)
{
    ostr << (size_t) bytes.size();
    for (natural_8_bit  byte : bytes)
        ostr << byte;
}

void kleeient::read_trace(message& istr, std::vector<bool>& trace)
{
    size_t size;
    istr >> size;
    for (size_t i = 0; i < size; i++) {
        bool dir;
        istr >> dir;
        trace.push_back(dir);
    }
}

bool kleeient::send_result(std::string json_string)
{
    std::cout << "Request finished, sending results..." << std::endl << std::endl;

    auto json_stream = std::basic_istringstream(json_string);
    boost::property_tree::ptree json;
    boost::property_tree::json_parser::read_json(json_stream, json);
    bool feasible = json.get<bool>("feasible");

    message msg;

    if (feasible) {
        msg.header.type = 1;

        std::vector<uint8_t> bytes;
        BOOST_FOREACH(const boost::property_tree::ptree::value_type &v,
                    json.get_child("input_tc").get_child("bytes"))
        {
            bytes.push_back(v.second.get_value<uint8_t>());
        }

        write_stdin(msg, bytes);
    } else {
        msg.header.type = 0;
    }

    boost::system::error_code ec;
    connection_to_server->send_message(msg, ec);
    if (ec) {
        std::cerr << "ERROR: sending result to server\n" << ec.message() << "\n";
        return false;
    }
    return true;
}

}
