#include <connection/client_executor.hpp>

#include <cstdlib>

namespace connection {

client_executor::client_executor(int keep_alive, std::string path_to_client, ts_queue<std::shared_ptr<session>>& sessions):
    keep_alive(keep_alive),
    path_to_client(std::move(path_to_client)),
    sessions(sessions),
    finished(false),
    clients_threads()
    {}


void client_executor::start() {
    thread = std::thread(
        [this]() {
            if (path_to_client.empty()) {
                return;
            }
            while (!finished) {
                if (sessions.size() < keep_alive) {
                    if (clients_threads.size() > keep_alive) {
                        clients_threads.front().join();
                        clients_threads.pop_front();
                    }
                    clients_threads.emplace_back(std::bind(std::system, path_to_client.data()));
                    
                    // wait for the client to connect to the server
                    sessions.wait_for_add();
                }
            }
        }
    );
}


void client_executor::stop() {
    finished = true;
    if (thread.joinable()) {
        thread.join();
    }
    sessions.clear();
    for (auto& t: clients_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
}

client_executor::~client_executor() {
    stop();
}


}