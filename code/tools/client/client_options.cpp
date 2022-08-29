#include <boost/algorithm/hex.hpp>
#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <cstdint>
#include <iostream>
#include <iterator>

#include <client/client_options.hpp>

client_options& client_options::instance() {
    static client_options co;
    return co;
}

int client_options::parse_client_options(int argc, char *argv[]) {
    try {
        po::options_description desc("Allowed options");
        desc.add_options()("input", po::value<std::string>(), "Input bytes as hex");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("input")) {
            boost::algorithm::unhex(vm["input"].as<std::string>(),
                                    std::back_inserter(input_bytes));
        }

    } catch (boost::algorithm::hex_decode_error &e) {
        std::cout << "Error: input is not hexadecimal\n";
        return 1;
    } catch (...) {
        std::cout << "Error: exception of unknown type!\n";
        return 1;
    }
    return 0;
}