#include <boost/algorithm/hex.hpp>
#include <boost/process.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>

#include <connection/kleeient.hpp>
#include <connection/message.hpp>
#include <connection/connection.hpp>
#include <iomodels/iomanager.hpp>

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

kleeient kleeient::get_instance(boost::asio::io_context& io_context)
{
    auto output_dir = std::string("/home/kebab/fuzzer/sbt-fizzer-private/dist/klee-output/");
    auto klee_path = std::string("/home/kebab/llvm-playground/JetKlee/build/bin/klee");
    auto traces = std::string("traces");
    auto models = std::string("models");
    auto traces_path = output_dir + traces;
    auto models_path = output_dir + models;
    auto program_path = std::string("/home/kebab/fuzzer/sbt-fizzer-private/dist/benchmarks/fast/nested_ifs.ll");

    if (mkfifo(traces_path.c_str(), S_IRUSR | S_IWUSR) == -1) {
        throw std::runtime_error("Could not create traces pipe");
    }
    if (mkfifo(models_path.c_str(), S_IRUSR | S_IWUSR) == -1) {
        throw std::runtime_error("Could not create models pipe");
    }

    std::unique_ptr<boost::process::child> process = std::make_unique<boost::process::child>(
        klee_path,
        boost::process::args({
            "--output-dir=" + output_dir,
            "--use-interactive-search",
            "--interactive-search-file=" + traces_path, // TODO: fix relative/absolute path handling in klee
            "--write-ktests=false",
            "--dump-states-on-halt=false",
            "--write-json",
            "--json-path=" + models, // relative to `output_dir`
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

    while (true) {
        if (!receive_input())
            return;
        auto klee_response = invoke_klee();
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

bool kleeient::receive_input() {
    std::cout << "Receiving input from server..." << std::endl;

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

    iomodels::iomanager::instance().load_trace(input);
    std::cout << "Received input from server" << std::endl;
    return true;
}

// input trace is obtained from iomanager
std::string kleeient::invoke_klee()
{
    std::cout << "Received following trace:" << std::endl;
    for (auto &record : iomodels::iomanager::instance().get_trace())
    {
        std::cout << record.covered_branch;
        *traces << (record.covered_branch ? "1" : "0");
    }
    *traces << std::endl << std::flush;

    std::cout << std::endl;
    std::cout << "=== end ===" << std::endl;

    std::cout << "Klee responded with following JSON:" << std::endl;
    std::string json_string;
    std::getline(*models, json_string);
    std::cout << json_string << std::endl;
    std::cout << "=== end ===" << std::endl;

    return json_string;
}

void kleeient::write_stdin(message&  ostr, std::vector<uint8_t> bytes, std::vector<uint8_t> counts)
{
    ostr << (size_t)(bytes.size() * 8); // write bits_read
    ostr << (natural_16_bit)bytes.size();
    for (natural_8_bit  byte : bytes)
        ostr << byte;

    ostr << (natural_16_bit)counts.size();
    for (natural_8_bit cnt : counts)
        ostr << cnt;
}

bool kleeient::send_result(std::string json_string)
{
    std::cout << "JetKlee finished, sending results..." << std::endl;

    auto json_stream = std::basic_istringstream(json_string);
    boost::property_tree::ptree json;
    boost::property_tree::json_parser::read_json(json_stream, json);

    bool feasible = json.get<bool>("feasible");

    message msg;

    if (feasible) {
        msg.header.type = message_type::results_from_kleeient_normal;

        std::vector<uint8_t> bytes;
        std::vector<uint8_t> counts;
        BOOST_FOREACH(const boost::property_tree::ptree::value_type &v,
                    json.get_child("input_tc").get_child("bytes"))
        {
            bytes.push_back(v.second.get_value<uint8_t>());
        }
        BOOST_FOREACH(const boost::property_tree::ptree::value_type &v,
                    json.get_child("input_tc").get_child("chunks"))
        {
            counts.push_back(v.second.get_value<uint8_t>() * 8);
            // * 8 because json stores number of bytes and fuzzer expects number of bits
        }

        write_stdin(msg, bytes, counts);
    } else {
        msg.header.type = message_type::results_from_kleeient_infeasible;
    }

    boost::system::error_code ec;
    connection_to_server->send_message(msg, ec);
    if (ec) {
        std::cerr << "ERROR: sending result to server\n" << ec.message() << "\n";
        return false;
    }

    std::cout << "Results sent to server" << std::endl;
    return true;
}

}
