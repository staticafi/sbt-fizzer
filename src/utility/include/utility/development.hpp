#ifndef UTILITY_DEVELOPMENT_HPP_INCLUDED
#   define UTILITY_DEVELOPMENT_HPP_INCLUDED

#   include <utility/fail_message.hpp>
#   include <utility/log.hpp>
#   include <stdexcept>
#   include <string>
#   include <iostream>

#   define NOT_IMPLEMENTED_YET() { LOG(LSL_ERROR,"NOT IMPLEMENTED YET !");\
                                   throw under_construction(FAIL_MSG("NOT IMPLEMENTED YET !")); }
#   define NOT_SUPPORTED() { LOG(LSL_ERROR,"NOT SUPPORTED !");\
                             throw under_construction(FAIL_MSG("NOT SUPPORTED !")); }
#   define TODO(MSG) { LOG(LSL_INFO,"TODO: " << MSG); }

struct under_construction : public std::logic_error {
    explicit under_construction(std::string const& msg) : std::logic_error(msg) {}
};

#endif
