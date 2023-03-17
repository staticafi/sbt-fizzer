#ifndef IOMODELS_IOEXCEPTIONS_HPP_INCLUDED
#   define IOMODELS_IOEXCEPTIONS_HPP_INCLUDED

#   include <stdexcept>

namespace  iomodels {


struct  boundary_condition_violation : public std::runtime_error {
    explicit boundary_condition_violation(std::string const&  msg) : std::runtime_error(msg) {}
};


struct  execution_crashed : public std::runtime_error {
    explicit execution_crashed(std::string const&  msg) : std::runtime_error(msg) {}
};


}

#endif
