#ifndef CONNECTION_TS_QUEUE_HPP_INCLUDED
#   define CONNECTION_TS_QUEUE_HPP_INCLUDED

#   include <deque>
#   include <mutex>
#   include <condition_variable>

template <typename T>
struct ts_queue {

    T pop() {
        std::scoped_lock lock(deque_mux);
        T value = std::move(deque.front());
        deque.pop_front();
        return value;
    }

    void push(T&& value) {
        std::unique_lock lock(deque_mux);
        bool was_empty = deque.empty();
        deque.push_back(std::forward<T>(value));
        lock.unlock();
        if (was_empty) {
            blocking.notify_one();
        }
    }

    bool empty() {
        std::scoped_lock lock(deque_mux);
        return deque.empty();
    }

    size_t size() {
        std::scoped_lock lock(deque_mux);
        return deque.size();
    }

    T wait_and_pop() {
        std::unique_lock lock(deque_mux);
        while (deque.empty()) {
            blocking.wait(lock);
        }
        T result = std::move(deque.front());
        deque.pop_front();
        return result;
    }

private:
    std::deque<T> deque;
    std::mutex deque_mux;
    std::condition_variable blocking;

};

#endif