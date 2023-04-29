#ifndef CONNECTION_CLIENT_CRASH_EXCEPTION_HPP_INCLUDED
#   define CONNECTION_CLIENT_CRASH_EXCEPTION_HPP_INCLUDED

#   include <string>
#   include <stdexcept>


namespace connection {

struct client_crash_exception: public std::runtime_error{
    explicit client_crash_exception(std::string const& msg) : std::runtime_error(msg) {}
};


}

#endif