#include <boost/process/io.hpp>

#include <connection/client_executor.hpp>
#include <connection/server.hpp>

#include <cstdlib>
#include <chrono>
#include <iostream>

namespace connection {

client_executor::client_executor(int keep_alive, std::string path_to_client, ts_queue<std::shared_ptr<connection>>& connections):
    keep_alive(keep_alive),
    path_to_client(std::move(path_to_client)),
    connections(connections),
    finished(false),
    clients(),
    excptr(nullptr)
    {}


const std::exception_ptr& client_executor::get_exception_ptr() const {
    return excptr;
}


void client_executor::start() {
    if (path_to_client.empty()) {
        return;
    }
    using namespace std::chrono_literals;
    thread = std::thread(
        [this]() {
            int client_connection_failures = 0;
            try {
                while (!finished) {
                    if (clients.size() > keep_alive) {
                        clients.front().wait();
                        clients.pop_front();
                    }
                    // run the client
                    clients.emplace_back(path_to_client, boost::process::std_out > boost::process::null);

                    // wait until it connects, or kill it if it doesn't connect in time
                    if (!connections.wait_until_push_or_timeout(2000ms)) {
                        clients.back().terminate();
                        clients.pop_back();
                        std::cerr << "ERROR: client failed to connect in time during client execution\n";
                        ++client_connection_failures;
                    }
                    if (client_connection_failures >= 5) {
                        throw client_crash_exception("Too many client connection failures");
                    }
                }
            }
            catch (...) {
                excptr = std::current_exception();
            }
        }
    );
}


void client_executor::stop() {
    finished = true;
    // drop all connections, so that we don't hang on clients.front().wait()
    connections.clear();
    // make sure the thread has stopped completely
    if (thread.joinable()) {
        thread.join();
    }
    /* it's possible that the thread executed a new client before stopping,
    make sure to drop that connection as well */
    connections.clear();
    for (auto& client: clients) {
        client.wait();
    }
}

}