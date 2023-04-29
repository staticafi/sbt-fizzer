#ifndef CONNECTION_CLIENT_EXECUTOR_HPP_INCLUDED
#   define CONNECTION_CLIENT_EXECUTOR_HPP_INCLUDED

#   include <boost/process.hpp>

#   include <connection/ts_queue.hpp>
#   include <connection/connection.hpp>

#   include <memory>
#   include <cstddef>
#   include <string>
#   include <atomic>
#   include <thread>
#   include <condition_variable>
#   include <mutex>
#   include <deque>
#   include <exception>

#   include <connection/server.hpp>

namespace connection {

struct client_executor {
    client_executor(int keep_alive, std::string client_invocation, server& server);
    
    void start();
    void stop();

private:
    std::size_t keep_alive;
    std::string client_invocation;
    ts_queue<connection>& connections;
    std::thread thread;
    std::atomic_bool finished;
    std::deque<boost::process::child> clients;
    std::exception_ptr& main_excptr;
};

}


#endif