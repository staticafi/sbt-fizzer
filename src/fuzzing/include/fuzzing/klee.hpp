#ifndef FUZZING_KLEE_HPP_INCLUDED
#   define FUZZING_KLEE_HPP_INCLUDED

#   include <boost/asio.hpp>
#   include <boost/property_tree/ptree.hpp>
#   include <fstream>

namespace fuzzing {


struct klee
{
public:
    klee(const std::string& program_path);
    klee();
    void join();
    bool get_model(const std::vector<bool> trace, std::vector<uint8_t>& model);

private:
    std::ifstream models;
    std::ofstream traces;
    std::thread klee_thread;
};


}

#endif
