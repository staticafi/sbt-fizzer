#ifndef INSTRUMENTATION_EXCEPTIONS_TYPES_HPP_INCLUDED
#   define INSTRUMENTATION_EXCEPTIONS_TYPES_HPP_INCLUDED

#   include <stdexcept>

namespace  instrumentation {

struct  terminate_exception: public std::runtime_error
{
    explicit terminate_exception(char const* const message): std::runtime_error(message) {}
};

struct  error_reached_exception: public std::runtime_error
{
    explicit error_reached_exception(char const* const message): std::runtime_error(message) {}
};

}

#endif
