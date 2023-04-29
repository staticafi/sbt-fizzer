#ifndef CONNECTION_TARGET_EXECUTOR_HPP_INCLUDED
#   define CONNECTION_TARGET_EXECUTOR_HPP_INCLUDED


#   include <connection/shared_memory.hpp>


namespace connection {

struct target_executor {

    target_executor(std::string target_invocation);

    void init_shared_memory(std::size_t size);
    void execute_target();


    shared_memory shared_memory;
    natural_32_bit timeout_ms;
private:
    std::string target_invocation;
};



}



#endif

