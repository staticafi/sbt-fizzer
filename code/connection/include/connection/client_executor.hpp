#ifndef CONNECTION_CLIENT_EXECUTOR_HPP_INCLUDED
#   define CONNECTION_CLIENT_EXECUTOR_HPP_INCLUDED

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


namespace connection {

struct client_executor {

client_executor(int keep_alive, std::string path_to_client, ts_queue<std::shared_ptr<connection>>& connections);
void start();
void stop();
~client_executor();

private:
    std::size_t keep_alive;
    std::string path_to_client;
    ts_queue<std::shared_ptr<connection>>& connections;
    std::thread thread;
    std::deque<std::thread> clients_threads;
    std::atomic_bool finished; 
};

}


#endif