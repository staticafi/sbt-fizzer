#ifndef CONNECTION_CLIENT_EXECUTOR_HPP_INCLUDED
#   define CONNECTION_CLIENT_EXECUTOR_HPP_INCLUDED

#   include <boost/process/child.hpp>

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

namespace connection {

struct client_executor {

client_executor(int keep_alive, std::string path_to_client, ts_queue<std::shared_ptr<connection>>& connections);
void start();
void stop();
~client_executor();
const std::exception_ptr& get_exception_ptr() const;

private:
    std::size_t keep_alive;
    std::string path_to_client;
    ts_queue<std::shared_ptr<connection>>& connections;
    std::thread thread;
    std::deque<boost::process::child> clients;
    std::atomic_bool finished;
    std::exception_ptr excptr;
};

}


#endif