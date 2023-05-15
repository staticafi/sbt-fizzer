set(THIS_TARGET_NAME client)

set(CLIENT_SOURCES 
    ./program_options.hpp
    ./program_options.cpp

    ./program_info.hpp
    ./program_info.cpp

    ./run.cpp
    ./main.cpp
    )

set(CLIENT_LIBS
    connection
    iomodels
    instrumentation
    iomodels
    utility
    ${Boost_LIBRARIES}
    )

add_library(client_lib
    ${CLIENT_SOURCES}
    )

target_link_libraries(client_lib
    ${CLIENT_LIBS}
    )

set_target_properties(client_lib PROPERTIES
    DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

install(TARGETS client_lib DESTINATION "lib")


option(INSTRUMENTED_LLVM_FILE "Provide the path to the instrumented coded needed to compile the client")

if(INSTRUMENTED_LLVM_FILE)

    add_executable(${THIS_TARGET_NAME}
        ${CLIENT_SOURCES}
        )

    target_compile_options(${THIS_TARGET_NAME} PRIVATE -flto)
    target_link_options(${THIS_TARGET_NAME} PRIVATE -flto)

    target_link_libraries(${THIS_TARGET_NAME}
        ${INSTRUMENTED_LLVM_FILE}
        ${CLIENT_LIBS}
        Threads::Threads
        )


    set_target_properties(${THIS_TARGET_NAME} PROPERTIES
        DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
        RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
        RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
        )

    install(TARGETS ${THIS_TARGET_NAME} DESTINATION "tools")

endif()