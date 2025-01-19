#ifndef CONNECTION_MEDIUM_HPP_INCLUDED
#   define CONNECTION_MEDIUM_HPP_INCLUDED

#   include <instrumentation/target_termination.hpp>

namespace  connection {


struct  medium
{
    virtual ~medium() {}
    virtual void clear() {}
    virtual bool can_accept_bytes(std::size_t n) const { return true; }
    virtual bool can_deliver_bytes(std::size_t n) const { return true; }
    virtual void accept_bytes(const void* src, std::size_t n) {}
    virtual void deliver_bytes(void* dest, std::size_t n) {}
    virtual void set_termination(instrumentation::target_termination termination) {}
};


}

#endif