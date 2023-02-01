#ifndef UTILITY_THREAD_SYNCHRONISARION_BARRIER_HPP_INCLUDED
#   define UTILITY_THREAD_SYNCHRONISARION_BARRIER_HPP_INCLUDED

#   include <utility/basic_numeric_types.hpp>
#   include <boost/noncopyable.hpp>
#   include <mutex>
#   include <condition_variable>


struct thread_synchronisarion_barrier : private boost::noncopyable
{
    explicit thread_synchronisarion_barrier(natural_32_bit const num_threads_to_synchronise);
    ~thread_synchronisarion_barrier();
    void wait_for_other_threads();
private:
    natural_32_bit  m_num_threads_to_wait_for;
    std::mutex  m_mutex_to_m_num_threads_to_wait_for;
    std::condition_variable  m_condition_variable;
};


#endif
