#ifndef UTILITY_ASSUMPTIONS_HPP_INCLUDED
#   define UTILITY_ASSUMPTIONS_HPP_INCLUDED

#   include <utility/config.hpp>

#   if !((BUILD_DEBUG() == 1 && defined(DEBUG_DISABLE_ASSUMPTION_CHECKING)) || \
         (BUILD_RELEASE() == 1 && defined(RELEASE_DISABLE_ASSUMPTION_CHECKING)))
#       include <utility/fail_message.hpp>
#       include <utility/log.hpp>
#       include <stdexcept>
#       include <string>
        struct assumption_failure : public std::logic_error {
            explicit assumption_failure(std::string const& msg) : std::logic_error(msg) {}
        };
#       define ASSUMPTION(C) do { if (!(C)) { LOG(LSL_ERROR,"Assumption failure.");\
                                              throw assumption_failure(FAIL_MSG("Assumption failure.")); }\
                                } while (false)
#   else
#       define ASSUMPTION(C)
#   endif

#endif
