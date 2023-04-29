set(THIS_TARGET_NAME sbt-fizzer_client)

add_executable(${THIS_TARGET_NAME} 
    ./program_options.hpp
    ./program_options.cpp

    ./program_info.hpp
    ./program_info.cpp

    ./run.cpp
    ./main.cpp
    )

target_link_libraries(${THIS_TARGET_NAME}
    connection
    iomodels
    instrumentation
    iomodels
    utility
    Threads::Threads
    )


set_target_properties(${THIS_TARGET_NAME} PROPERTIES
    DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

install(TARGETS ${THIS_TARGET_NAME} DESTINATION "tools")