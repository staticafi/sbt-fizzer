#include <boost/process.hpp>

#include <connection/target_executor.hpp>


namespace bp = boost::process;
using namespace instrumentation;


namespace connection {

/* boost process wait_for waits for the full duration if the process exited 
before wait_for (https://github.com/boostorg/process/issues/69) 
the wrapper is a workaround for this issue */
template <typename Rep, typename Period>
static bool wait_for_wrapper(bp::child& process, const std::chrono::duration<Rep, Period>& rel_time) {
    if (process.running()) {
        return process.wait_for(rel_time);
    }
    return true;
}


target_executor::target_executor(std::string target_invocation): 
    target_invocation(std::move(target_invocation))
{}

void target_executor::init_shared_memory(std::size_t size) {
    shared_memory.open_or_create();
    shared_memory.set_size(size);
    shared_memory.map_region();
}


void target_executor::execute_target() {
    using namespace std::chrono_literals;
    bp::child target = bp::child(target_invocation, bp::std_out > bp::null);
    if (!wait_for_wrapper(target, std::chrono::milliseconds(timeout_ms))) {
        target.terminate();
        shared_memory.set_termination(target_termination::timeout);
    }

    if (!shared_memory.get_termination()) {
        if (target.exit_code() == 0) {
            shared_memory.set_termination(target_termination::normal);
        }
        else {
            shared_memory.set_termination(target_termination::crash);
        }
    }



}



}