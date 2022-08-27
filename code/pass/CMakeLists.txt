find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LT_LLVM_INSTALL_DIR}")

if(NOT "14" VERSION_EQUAL "${LLVM_VERSION_MAJOR}")
  message(WARNING "Found LLVM ${LLVM_VERSION_MAJOR}, but LLVM version 14 is advised")
endif()

message("LLVM STATUS:
  Definitions ${LLVM_DEFINITIONS}
  Includes    ${LLVM_INCLUDE_DIRS}
  Libraries   ${LLVM_LIBRARY_DIRS}
  Targets     ${LLVM_TARGETS_TO_BUILD}"
)

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