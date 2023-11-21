#ifndef UTILITY_CONFIG_HPP_INCLUDED
#   define UTILITY_CONFIG_HPP_INCLUDED

////////////////////////////////////////////////////////////////////////////////

/*

Configuration is available through pre-defined macros:

    RELEASE_DISABLE_INVARIANT_CHECKING
        - if defined, invariants will NOT be checked in the release build
    DEBUG_DISABLE_INVARIANTS_CHECKING
        - if defined, invariants will NOT be checked in the debug build

    RELEASE_DISABLE_ASSUMPTION_CHECKING
        - if defined, assumptions about input data will NOT be checked in the release build.
    DEBUG_DISABLE_ASSUMPTION_CHECKING
        - if defined, assumptions about input data will NOT be checked in the debug build.

    RELEASE_DISABLE_TIME_PROFILING
        - if defined, code managing time profiling will NOT be included in the release build
    DEBUG_DISABLE_TIME_PROFILING
        - if defined, code managing time profiling will NOT be included in the debug build

*/

////////////////////////////////////////////////////////////////////////////////

#   define PLATFORM_WINDOWS()     1
#   define PLATFORM_LINUX()       2
#   define PLATFORM_WEBASSEMBLY() 3

#   if defined(_WIN32) || defined(WIN32)
#       define PLATFORM()         PLATFORM_WINDOWS()
#   elif defined(__linux__)
#       define PLATFORM()         PLATFORM_LINUX()
#   elif defined(WEBASSEMBLY)
#       define PLATFORM()         PLATFORM_WEBASSEMBLY()
#   else
#       error "Unsuported platform."
#   endif

#   define CPU32()     1
#   define CPU64()     2

#   if defined(_WIN64) || defined(__x86_64__)
#       define CPU_TYPE()       CPU64()
#   else
#       define CPU_TYPE()       CPU32()
#   endif

////////////////////////////////////////////////////////////////////////////////

#   define COMPILER_UNKNOWN()     0
#   define COMPILER_VC()          1
#   define COMPILER_GCC()         2
#   define COMPILER_CLANG()       3
#   define COMPILER_WEBASSEMBLY() 4

#   if defined(_MSC_VER) // MSVC
#       define COMPILER()         COMPILER_VC()
#       define COMPILER_VERSION() _MSC_VER
#   elif defined(__GNUC__) // gcc
#       define COMPILER()         COMPILER_GCC()
#       define COMPILER_VERSION() __GNUC__.__GNUC_MINOR__.__GNUC_PATCHLEVEL__
#   elif defined(__clang__) // CLANG
#       define COMPILER()         COMPILER_CLANG()
#       define COMPILER_VERSION() __clang_major__.__clang_minor__
#   elif defined(__EMSCRIPTEN__) // WEBASSEMBLY
#       define COMPILER()         COMPILER_WEBASSEMBLY()
#       define COMPILER_VERSION() __EMSCRIPTEN_major__.__EMSCRIPTEN_minor__
#   else // unknown
#       define COMPILER()         COMPILER_UNKNOWN()
#       define COMPILER_VERSION() 0
#   endif

////////////////////////////////////////////////////////////////////////////////

#   if COMPILER() == COMPILER_VC()
#       define FUNCTION_PROTOTYPE() __FUNCSIG__
#   elif COMPILER() == COMPILER_GCC()
#       define FUNCTION_PROTOTYPE() __PRETTY_FUNCTION__
#   elif COMPILER() == COMPILER_CLANG()
#       define FUNCTION_PROTOTYPE() __PRETTY_FUNCTION__
#   elif COMPILER() == COMPILER_WEBASSEMBLY()
#       define FUNCTION_PROTOTYPE() __PRETTY_FUNCTION__
#   else // unknown => use __func__ (is guaranded by ISO standard)
#       define FUNCTION_PROTOTYPE() __func__
#   endif

////////////////////////////////////////////////////////////////////////////////

#   if defined(_DEBUG) || defined(DEBUG)
#       define BUILD_DEBUG()    1
#       define BUILD_RELEASE()  0
#   else
#       define BUILD_DEBUG()    0
#       define BUILD_RELEASE()  1
#   endif

#endif
