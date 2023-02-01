#ifndef CONNECTION_TS_QUEUE_HPP_INCLUDED
#   define CONNECTION_TS_QUEUE_HPP_INCLUDED

#   include <deque>
#   include <mutex>
#   include <condition_variable>
#   include <optional>

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
        deque.push_back(std::forward<T>(value));
        added = true;
        lock.unlock();
        blocking.notify_all();
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

    template< class Rep, class Period>
    std::optional<T> wait_and_pop_or_timeout(const std::chrono::duration<Rep, Period>& timeout) {
        std::optional<T> result;
        std::unique_lock lock(deque_mux);
        if (blocking.wait_for(lock, timeout, [this]{return !deque.empty();})) {
            result = std::move(deque.front());
            deque.pop_front();
        }
        return result;
    }

    std::optional<T> try_pop() {
        std::optional<T> result;
        std::unique_lock lock(deque_mux);
        if (!deque.empty()) {
            result = std::move(deque.front());
            deque.pop_front();
        } 
        return result;
    }

    void clear() {
        std::scoped_lock lock(deque_mux);
        deque.clear();
    }

    template< class Rep, class Period>
    bool wait_for_add_or_timeout(const std::chrono::duration<Rep, Period>& timeout) {
        std::unique_lock lock(deque_mux);
        if (blocking.wait_for(lock, timeout, [this]{return added;})) {
            added = false;
            return true;
        }
        return false;
    }

private:
    std::deque<T> deque;
    std::mutex deque_mux;
    std::condition_variable blocking;
    bool added = false;
};

#endif