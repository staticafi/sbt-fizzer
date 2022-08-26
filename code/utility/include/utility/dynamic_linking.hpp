#ifndef UTILITY_DYNAMIC_LINKING_HPP_INCLUDED
#   define UTILITY_DYNAMIC_LINKING_HPP_INCLUDED

#   include <utility/config.hpp>

#   if COMPILER() == COMPILER_VC()
#       define DLINK_IMPORT_SYMBOL()          __declspec(dllimport)
#       define DLINK_EXPORT_SYMBOL()          __declspec(dllexport)
#   elif COMPILER() == COMPILER_GCC()
#       define DLINK_IMPORT_SYMBOL()
#       define DLINK_EXPORT_SYMBOL()
#   else
#       define DLINK_IMPORT_SYMBOL()
#       define DLINK_EXPORT_SYMBOL()
#   endif

#endif
