#include <boost/process/io.hpp>

#include <connection/client_executor.hpp>
#include <connection/server.hpp>

#include <cstdlib>
#include <chrono>

namespace bp = boost::process;

namespace connection {

client_executor::client_executor(int keep_alive, std::string client_invocation, server& server):
    keep_alive(keep_alive),
    client_invocation(std::move(client_invocation)),
    connections(server.connections),
    finished(false),
    clients(),
    main_excptr(server.client_executor_excptr)
{}

/* The implementation of the client executor is not optimal, as it waits for
the client to connect before executing another one (wasting a lot of precious
time). There is a better solution using boost process in combination with 
boost asio. It includes using exit handlers with the boost::process::child class
to re-execute the process whenever it finishes. Unfortunately, there are issues
with invalid writes using the exit handlers, as described here:
https://github.com/boostorg/process/pull/175 
The implementation will be improved once we upgrade to Boost 1.82.*/
void client_executor::start() {
    using namespace std::chrono_literals;
    thread = std::thread(
        [this]() {
            try {
                while (!finished) {
                    if (clients.size() > keep_alive) {
                        clients.front().wait();
                        clients.pop_front();
                    }
                    // run the client
                    clients.emplace_back(client_invocation, bp::std_out > bp::null);

                    // wait until it connects, or kill it if it doesn't connect in time
                    if (!connections.wait_until_push_or_timeout(2000ms)) {
                        clients.back().terminate();
                        clients.pop_back();
                    }
                }
            }
            catch (...) {
                main_excptr = std::current_exception();
            }
        }
    );
}


void client_executor::stop() {
    finished = true;
    // drop all connections, so that we don't hang on wait()
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