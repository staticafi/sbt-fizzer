# Set the LLVM header and library paths
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# LLVM is (typically) built with no C++ RTTI. We need to match that;
# otherwise, we'll get linker errors about missing RTTI data.
add_compile_options("-fno-rtti")

add_library(fizzer_pass MODULE src/FizzerPass.cpp)

set_target_properties(fizzer_pass PROPERTIES
    DEBUG_POSTFIX "_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_POSTFIX "_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_POSTFIX "_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

install(TARGETS fizzer_pass DESTINATION "lib")