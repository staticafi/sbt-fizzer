message("Including the following tools to the build:")

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/testapps")
    add_subdirectory(./testapps)
endif()

add_subdirectory(./client)
    message("  client")
add_subdirectory(./fizz)
    message("  fizz")
