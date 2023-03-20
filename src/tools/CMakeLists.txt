message("Including the following tools to the build:")

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/testapps")
    add_subdirectory(./testapps)
endif()

add_subdirectory(./client)
    message("  client")
add_subdirectory(./kleeient)
    message("  kleeient")
add_subdirectory(./server)
    message("  server")
add_subdirectory(./utils)
    message("  utils")