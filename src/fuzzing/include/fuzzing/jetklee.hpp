#ifndef FUZZING_JETKLEE_HPP_INCLUDED
#   define FUZZING_JETKLEE_HPP_INCLUDED

#   include <thread>
#   include <fstream>
#   include <vector>

namespace fuzzing {


struct jetklee
{
public:
    jetklee(const std::string& program_path);
    jetklee();
    void join();
    bool get_model(const std::vector<bool> trace, std::vector<uint8_t>& model);
    bool is_running();

private:
    std::ifstream models;
    std::ofstream traces;
    std::thread jetklee_thread;
    bool running;
};


}

#endif
