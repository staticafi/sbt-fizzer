set(THIS_TARGET_NAME server)

add_executable(${THIS_TARGET_NAME}
    program_info.hpp
    program_info.cpp

    program_options.hpp
    program_options.cpp

    main.cpp
    run.cpp
    )

target_link_libraries(${THIS_TARGET_NAME}
    instrumentation
    connection
    iomodels
    fuzzing
    instrumentation # Duplicating because of Mingw (otherwise linking errors)
    connection  # Duplicating because of Mingw (otherwise linking errors)
    fuzzing     # Duplicating because of Mingw (otherwise linking errors)
    utility
    Threads::Threads
    )

set_target_properties(${THIS_TARGET_NAME} PROPERTIES
    DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

install(TARGETS ${THIS_TARGET_NAME} DESTINATION "tools")
