project(fizz)

cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

if(NOT CMAKE_BUILD_TYPE)
    message("Build type not set => setting 'Release' as default.")
    set(CMAKE_BUILD_TYPE "Release"  CACHE STRING "Release" FORCE)
endif()
message("Build type = " ${CMAKE_BUILD_TYPE})
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    add_definitions(-DDEBUG)
elseif(CMAKE_BUILD_TYPE MATCHES "Release")
    add_definitions(-DRELEASE)
elseif(CMAKE_BUILD_TYPE MATCHES "RelWithDebInfo")
    add_definitions(-DRELEASE)
else()
    message(SEND_ERROR "Unknown build type. Use either Debug, Release, or RelWithDebInfo. E.g.: -DCMAKE_BUILD_TYPE=Release")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(CMAKE_COMPILER_IS_GNUCXX)
    add_definitions("-std=c++11 -Wall -Wno-unused-local-typedefs")
    if ((CMAKE_BUILD_TYPE STREQUAL Debug) OR
        (CMAKE_BUILD_TYPE STREQUAL RelWithDebInfo))
        add_definitions("-ggdb3")
    endif()
    message("Compiler = GCC")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    add_definitions("/bigobj")
    #add_definitions("/Wall")
    add_definitions("-D_ENABLE_EXTENDED_ALIGNED_STORAGE")
    message("Compiler = MSVC")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_definitions("
        -Wno-dangling-else
        -Wno-overloaded-virtual
        -Wno-unused-lambda-capture
        -Wno-potentially-evaluated-expression
        -Wno-#pragma-messages
        -Wno-deprecated-declarations
        ")
    message("Compiler = Clang/LLVM")
else()
    message(SEND_ERROR "Unknown (unsupported) compiler detected. Supported is only GCC (on Linux) and MSVC (on Windows).")
endif()

macro(append_compiler_flags FLAGS)
  set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${FLAGS}")
endmacro()

macro(append_linker_flags FLAGS)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${FLAGS}")
endmacro()

# find and add Eigen math library
message("Searching for Eigen ...")
find_package(Eigen3 CONFIG REQUIRED)
set(EIGEN_LIST_OF_LIBRARIES_TO_LINK_WITH "Eigen3::Eigen")

# find and add Boost
message("Searching for Boost library ...")
find_package(Boost COMPONENTS program_options REQUIRED)
set(BOOST_LIST_OF_LIBRARIES_TO_LINK_WITH
        ${Boost_LIBRARIES}
    )

set(CMAKE_INSTALL_PREFIX "${PROJECT_SOURCE_DIR}/dist" CACHE STRING "Install path" FORCE)
set(CMAKE_INSTALL_RPATH "./")
#set(CMAKE_BINARY_DIR "${PROJECT_SOURCE_DIR}/build" CACHE STRING "Build directory" FORCE)
set(FIZZ_3RD_INCLUDE_DIR "${CMAKE_TOOLCHAIN_FILE}/../../../installed/${VCPKG_TARGET_TRIPLET}/include")
include_directories(${FIZZ_3RD_INCLUDE_DIR})
message("3rd includes directory = ${FIZZ_3RD_INCLUDE_DIR}")
message("Sources directory = ${PROJECT_SOURCE_DIR}/code")
message("Install directory = ${CMAKE_INSTALL_PREFIX}")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/code")

# Add project specific code
add_subdirectory(./code)

message("Generating build files ...")
